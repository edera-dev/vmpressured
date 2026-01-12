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
