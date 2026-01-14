/*
 * SPDX-License-Identifier: GPL-2.0
 * SPDX-FileCopyrightText: Copyright (C) 2026 Edera, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see
 * <https://www.gnu.org/licenses/>.
 */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "vmpressured-observer.h"

struct node_state {
	enum vmpressure_state state;

	uint64_t last_wakeup_nsec;
	uint64_t last_balance_nsec;
	uint64_t last_direct_nsec;

	uint64_t wake_burst_start_nsec;
	uint32_t wake_burst_count;

	uint64_t bal_burst_start_nsec;
	uint32_t bal_burst_count;

	struct vmpressure_node_snapshot snapshot;
};

struct vmpressure_observer {
	struct vmpressure_config cfg;

	transition_handler_fn handler;
	void *handler_ctx;

	struct node_state *nodes;
	uint32_t nodecount;
};

static inline uint64_t nsec_sub(uint64_t a, uint64_t b)
{
	return (a >= b) ? (a - b) : 0;
}

static void emit_transition(const struct vmpressure_observer *observer,
			    enum vmpressure_state old_state,
			    enum vmpressure_state new_state,
			    const struct vmpressure_event *event,
			    struct node_state *n)
{
	if (n == NULL)
		return;

	n->state = new_state;

	if (observer->handler == NULL)
		return;

	struct vmpressure_transition transition = {
		.old_state = old_state,
		.new_state = new_state,
		.event = *event,
	};

	observer->handler(observer->handler_ctx, &transition);
}

int vmpressure_observer_init(struct vmpressure_observer **out,
			     const struct vmpressure_config *cfg,
			     transition_handler_fn handler,
			     void *handler_ctx)
{
	if (out == NULL)
		return -EINVAL;

	if (cfg == NULL)
		return -EINVAL;

	if (cfg->nodecount == 0)
		return -ENOBUFS;

	struct vmpressure_observer *observer = calloc(1, sizeof(*observer));
	if (observer == NULL)
		return -ENOMEM;

	observer->cfg = *cfg;
	observer->handler = handler;
	observer->handler_ctx = handler_ctx;

	observer->nodecount = cfg->nodecount;
	observer->nodes = calloc(observer->nodecount, sizeof(*observer->nodes));
	if (observer->nodes == NULL)
	{
		free(observer);
		return -ENOMEM;
	}

	for (uint32_t i = 0; i < observer->nodecount; i++)
		observer->nodes[i].state = PRESSURE_OK;

	*out = observer;
	return 0;
}

void vmpressure_observer_fini(struct vmpressure_observer *observer)
{
	if (observer == NULL)
		return;

	free(observer->nodes);
	free(observer);
}

enum vmpressure_state vmpressure_observer_state(struct vmpressure_observer *observer)
{
	if (observer == NULL || observer->nodes == NULL)
		return PRESSURE_OK;

	enum vmpressure_state highest_state = PRESSURE_OK;

	for (uint32_t i = 0; i < observer->nodecount; i++)
	{
		if (observer->nodes[i].state > highest_state)
			highest_state = observer->nodes[i].state;
	}

	return highest_state;
}

static inline void update_burst(uint64_t now, uint64_t window_nsec,
				uint64_t *start_nsec, uint32_t *count)
{
	if (*count == 0 || nsec_sub(now, *start_nsec) > window_nsec)
	{
		*start_nsec = now;
		*count = 1;
	}
	else
		(*count)++;
}

void vmpressure_observer_ingest(struct vmpressure_observer *observer,
				const struct vmpressure_event *e)
{
	if (observer == NULL)
		return;

	if (e == NULL)
		return;

	if (e->nid > observer->nodecount)
		return;

	struct node_state *n = &observer->nodes[e->nid];
	const uint64_t now = e->ts_nsec;

	if (e->snapshot.complete)
		n->snapshot = e->snapshot;

	enum vmpressure_state old_state = n->state;

	switch (e->cause)
	{
		case CAUSE_WAKEUP_KSWAPD:
			n->last_wakeup_nsec = now;
			update_burst(now, observer->cfg.soft_window_nsec,
				     &n->wake_burst_start_nsec, &n->wake_burst_count);

			if (n->state < PRESSURE_SOFT && n->wake_burst_count >= observer->cfg.soft_wakeups)
				emit_transition(observer, old_state, PRESSURE_SOFT, e, n);

			break;

		case CAUSE_BALANCE_PGDAT:
			n->last_balance_nsec = now;
			update_burst(now, observer->cfg.hard_window_nsec,
				     &n->bal_burst_start_nsec, &n->bal_burst_count);

			if (n->state < PRESSURE_HARD && n->bal_burst_count >= observer->cfg.hard_wakeups)
				emit_transition(observer, old_state, PRESSURE_HARD, e, n);

			break;

		case CAUSE_TRY_TO_FREE_PAGES:
			n->last_direct_nsec = now;

			if (n->state < PRESSURE_CRITICAL)
				emit_transition(observer, old_state, PRESSURE_CRITICAL, e, n);

			break;

		default:
			break;
	}
}

static inline enum vmpressure_state fallback_state(const struct vmpressure_observer *observer,
						   const struct node_state *n,
						   uint64_t now)
{
	bool wake_recent = nsec_sub(now, n->last_wakeup_nsec) < observer->cfg.recent_wakeup_nsec;
	bool bal_recent = nsec_sub(now, n->last_balance_nsec) < observer->cfg.recent_balance_nsec;

	if (bal_recent)
		return PRESSURE_HARD;

	if (wake_recent)
		return PRESSURE_SOFT;

	return PRESSURE_OK;
}

void vmpressure_observer_tick(struct vmpressure_observer *observer, uint64_t now)
{
	if (observer == NULL)
		return;

	for (uint32_t nid = 0; nid < observer->nodecount; nid++)
	{
		struct node_state *n = &observer->nodes[nid];
		enum vmpressure_state old_state = n->state;
		enum vmpressure_state new_state = old_state;

		switch (old_state)
		{
			case PRESSURE_CRITICAL:
				if (nsec_sub(now, n->last_direct_nsec) >= observer->cfg.down_from_critical_nsec)
					new_state = fallback_state(observer, n, now);
				break;

			case PRESSURE_HARD:
				if (nsec_sub(now, n->last_balance_nsec) >= observer->cfg.down_from_hard_nsec)
					new_state = fallback_state(observer, n, now);
				break;

			case PRESSURE_SOFT:
				if (nsec_sub(now, n->last_wakeup_nsec) >= observer->cfg.down_from_soft_nsec)
					new_state = fallback_state(observer, n, now);
				break;

			default:
				break;
		}

		if (new_state != old_state)
		{
			struct vmpressure_event ev = {
				.ts_nsec = now,
				.nid = nid,
				.cause = CAUSE_QUIET_DOWN,
			};

			emit_transition(observer, old_state, new_state, &ev, n);

			if (new_state < PRESSURE_SOFT)
			{
				n->wake_burst_count = 0;
				n->wake_burst_start_nsec = 0;
			}

			if (new_state < PRESSURE_HARD)
			{
				n->bal_burst_count = 0;
				n->bal_burst_start_nsec = 0;
			}
		}
	}
}
