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

#pragma once
#include <stdint.h>
#include <stdbool.h>

enum vmpressure_state {
	PRESSURE_OK = 0,
	PRESSURE_SOFT = 1,
	PRESSURE_HARD = 2,
	PRESSURE_CRITICAL = 3,
};

enum vmpressure_event_cause {
	CAUSE_WAKEUP_KSWAPD = 1,
	CAUSE_BALANCE_PGDAT = 2,
	CAUSE_TRY_TO_FREE_PAGES = 3,
	CAUSE_QUIET_DOWN = 4,
};

struct vmpressure_node_snapshot {
	bool complete;
	uint64_t free_pages;
	uint64_t file_pages;
	uint64_t anon_mapped_pages;
	uint64_t shmem_pages;
};

struct vmpressure_event {
	uint64_t ts_nsec;
	uint32_t nid;

	enum vmpressure_event_cause cause;

	uint32_t order;

	struct vmpressure_node_snapshot snapshot;
};

struct vmpressure_transition {
	enum vmpressure_state old_state;
	enum vmpressure_state new_state;

	struct vmpressure_event event;
};

struct vmpressure_config {
	uint32_t nodecount;

	uint64_t soft_window_ns;
	uint32_t soft_wakeups;

	uint64_t hard_window_ns;
	uint32_t hard_wakeups;

	uint64_t down_from_critical_ns;
	uint64_t down_from_hard_ns;
	uint64_t down_from_soft_ns;

	uint64_t recent_wakeup_ns;
	uint64_t recent_balance_ns;
};

typedef void (*transition_handler_fn)(void *ctx, const struct vmpressure_transition *t);

struct vmpressure_observer;

extern int vmpressure_observer_init(struct vmpressure_observer **out,
				    const struct vmpressure_config *cfg,
				    transition_handler_fn handler,
				    void *handler_ctx);

extern void vmpressure_observer_fini(struct vmpressure_observer *observer);

extern enum vmpressure_state vmpressure_observer_state(struct vmpressure_observer *observer);

extern void vmpressure_observer_ingest(struct vmpressure_observer *observer,
				       const struct vmpressure_event *e);

extern void vmpressure_observer_tick(struct vmpressure_observer *observer, uint64_t now_ns);
