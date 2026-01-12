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

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "vmpressure.h"

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} events SEC(".maps");

static __always_inline __s64 read_vmstat(struct pglist_data *pgdat, int idx)
{
	if (!pgdat)
		return -1;

	long v = 0;
	bpf_core_read(&v, sizeof(v), &pgdat->vm_stat[idx]);
	return (__s64) v;
}

static __always_inline void fill_vmstats(struct event *e,
					 struct pglist_data *pgdat)
{
	e->nr_free_pages = read_vmstat(pgdat, NR_FREE_PAGES);
	e->nr_file_pages = read_vmstat(pgdat, NR_FILE_PAGES);
	e->nr_anon_mapped = read_vmstat(pgdat, NR_ANON_MAPPED);
	e->nr_shmem = read_vmstat(pgdat, NR_SHMEM);

#ifdef NR_SLAB_RECLAIMABLE_B
	e->nr_slab_reclaimable = read_vmstat(pgdat, NR_SLAB_RECLAIMABLE_B);
#else
	e->nr_slab_reclaimable = -1;
#endif

#ifdef NR_SLAB_UNRECLAIMABLE_B
	e->nr_slab_unreclaimable = read_vmstat(pgdat, NR_SLAB_UNRECLAIMABLE_B);
#else
	e->nr_slab_unreclaimable = -1;
#endif
}

static __always_inline void clear_vmstats(struct event *e)
{
	e->nr_free_pages = -1;
	e->nr_file_pages = -1;
	e->nr_anon_mapped = -1;
	e->nr_shmem = -1;
	e->nr_slab_reclaimable = -1;
	e->nr_slab_unreclaimable = -1;
}

SEC("fentry/wakeup_kswapd")
int BPF_PROG(on_wakeup_kswapd,
	     struct zone *zone,
	     gfp_t gfp_flags, int order, int highest_zoneidx)
{
	struct pglist_data *pgdat = BPF_CORE_READ(zone, zone_pgdat);
	if (!pgdat)
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	clear_vmstats(e);

	e->type = EV_KSWAPD_WAKE;
	e->ts_ns = bpf_ktime_get_ns();
	e->cpu = bpf_get_smp_processor_id();
	e->nid = (__u32) BPF_CORE_READ(pgdat, node_id);
	e->order = (__u32) order;

	fill_vmstats(e, pgdat);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("fentry/try_to_free_pages")
int BPF_PROG(on_try_to_free_pages,
	     struct zonelist *zonelist,
	     int order, gfp_t gfp_mask, nodemask_t *nodemask)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	clear_vmstats(e);

	e->type = EV_TRY_TO_FREE_PAGES;
	e->ts_ns = bpf_ktime_get_ns();
	e->cpu = bpf_get_smp_processor_id();
	e->nid = (__u32) bpf_get_numa_node_id();
	e->order = (__u32) order;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("fentry/balance_pgdat")
int BPF_PROG(on_balance_pgdat,
	     struct pglist_data *pgdat, int order, int highest_zoneidx)
{
	if (!pgdat)
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->ts_ns = bpf_ktime_get_ns();
	e->cpu = bpf_get_smp_processor_id();
	e->type = EV_BALANCE_PGDAT;
	e->order = (__u32) order;

	fill_vmstats(e, pgdat);

	bpf_ringbuf_submit(e, 0);
	return 0;
}
