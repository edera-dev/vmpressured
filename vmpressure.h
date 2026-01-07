#pragma once

enum ev_type {
	EV_KSWAPD_WAKE = 1,
	EV_TRY_TO_FREE_PAGES = 2,
	EV_BALANCE_PGDAT = 3,
};

struct event {
	__u64 ts_ns;
	__u32 type;
	__u32 cpu;
	__u32 nid;
	__u32 order;

	/* vmstat snapshot (pages) */
	__s64 nr_free_pages;
	__s64 nr_file_pages;
	__s64 nr_anon_mapped;
	__s64 nr_shmem;
	__s64 nr_slab_reclaimable;
	__s64 nr_slab_unreclaimable;
};
