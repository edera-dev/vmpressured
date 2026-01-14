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

#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>

#include "vmpressure.h"
#include "vmpressure.skel.h"
#include "vmpressured-observer.h"

#define FD_RINGBUF		(1)
#define FD_TIMERFD		(2)

static volatile sig_atomic_t stop;

static uint64_t now_nsec(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static const char *stnames[PRESSURE_CRITICAL + 1] = {
	[PRESSURE_OK] = "OK",
	[PRESSURE_SOFT] = "SOFT",
	[PRESSURE_HARD] = "HARD",
	[PRESSURE_CRITICAL] = "CRITICAL",
};

static void sigint_handler(int signo)
{
	(void) signo;
	stop = 1;
}

static long pages_to_kb(long pages)
{
	if (pages < 0)
		return -1;
	long ps = sysconf(_SC_PAGESIZE);
	return (pages * ps) / 1024;
}

static enum vmpressure_event_cause event_to_cause(const struct event *e)
{
	switch (e->type)
	{
		case EV_KSWAPD_WAKE: return CAUSE_WAKEUP_KSWAPD;
		case EV_TRY_TO_FREE_PAGES: return CAUSE_TRY_TO_FREE_PAGES;
		case EV_BALANCE_PGDAT: return CAUSE_BALANCE_PGDAT;
		default: return 0;
	}
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	struct vmpressure_observer *observer = ctx;

	(void) data_sz;

	struct vmpressure_event ev = {
		.cause = event_to_cause(e),
		.ts_nsec = e->ts_nsec ? e->ts_nsec : now_nsec(),
		.nid = e->nid,
		.order = e->order,
		.snapshot = (struct vmpressure_node_snapshot){
			.complete = e->nr_free_pages != -1,
			.free_pages = e->nr_free_pages,
			.file_pages = e->nr_file_pages,
			.anon_mapped_pages = e->nr_anon_mapped,
			.shmem_pages = e->nr_shmem,
		},
	};

	vmpressure_observer_ingest(observer, &ev);

	return 0;
}

static void on_transition(void *ctx, const struct vmpressure_transition *tr)
{
	(void) ctx;

	fprintf(stderr, "[%lld] STATE nid=%u %s->%s reason=%u",
		(long long) tr->event.ts_nsec,
		tr->event.nid,
		stnames[tr->old_state],
		stnames[tr->new_state],
		tr->event.cause);

	if (tr->event.snapshot.complete) {
		fprintf(stderr, " free=%lld file=%lld anon=%lld shmem=%lld",
			(long long)pages_to_kb(tr->event.snapshot.free_pages),
			(long long)pages_to_kb(tr->event.snapshot.file_pages),
			(long long)pages_to_kb(tr->event.snapshot.anon_mapped_pages),
			(long long)pages_to_kb(tr->event.snapshot.shmem_pages));
	}

	fputc('\n', stderr);
}

static int make_timerfd(void)
{
	int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	if (tfd < 0)
		return -errno;

	struct itimerspec its = {};
	its.it_interval.tv_sec = 1;
	its.it_value.tv_sec = 1;

	if (timerfd_settime(tfd, 0, &its, NULL) < 0)
	{
		int e = -errno;
		close(tfd);
		return e;
	}

	return tfd;
}

static int read_max_node_id(uint32_t *out_max_nid)
{
	FILE *f = fopen("/sys/devices/system/node/possible", "re");
	if (f == NULL)
		return -errno;

	char buf[128];
	if (!fgets(buf, sizeof(buf), f)) {
		fclose(f);
		return -EIO;
	}
	fclose(f);

	// Find the largest integer in the string
	uint32_t max = 0;
	char *p = buf;

	while (*p)
	{
		if (*p >= '0' && *p <= '9')
		{
			char *end = NULL;
			unsigned long v = strtoul(p, &end, 10);

			if (end == p)
				break;

			if (v > max)
				max = (uint32_t)v;

			p = end;
		}
		else
			p++;
	}

	*out_max_nid = max;
	return 0;
}

static int set_oom_score_adj(int adj)
{
	FILE *f = fopen("/proc/self/oom_score_adj", "we");
	if (f == NULL)
		return -errno;

	if (fprintf(f, "%d\n", adj) < 0)
	{
		int e = -errno;
		fclose(f);
		return e;
	}

	if (fclose(f) != 0)
		return -errno;

	return 0;
}

static void maybe_protect_from_oom(void)
{
	int r = set_oom_score_adj(-1000);

	if (r < 0)
		fprintf(stderr, "warning: cannot set oom_score_adj: %s\n", strerror(-r));
}

int main(void)
{
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

	maybe_protect_from_oom();

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	uint32_t max_nid = 0;
	int r = read_max_node_id(&max_nid);
	if (r < 0)
	{
		fprintf(stderr, "failed to read max NUMA node id: %s\n", strerror(-r));
		return 1;
	}

	struct vmpressure_config cfg = {
		.nodecount = max_nid + 1,

		.soft_window_nsec = 10ull*1000000000,
		.soft_wakeups = 5,

		.hard_window_nsec = 10ull*1000000000,
		.hard_wakeups = 2,

		.down_from_critical_nsec = 30ull*1000000000,
		.down_from_hard_nsec = 30ull*1000000000,
		.down_from_soft_nsec = 60ull*1000000000,

		.recent_wakeup_nsec = 10ull*1000000000,
		.recent_balance_nsec = 10ull*1000000000,
	};

	struct vmpressure_observer *observer = NULL;
	if (vmpressure_observer_init(&observer, &cfg, on_transition, NULL) != 0)
	{
		fprintf(stderr, "initializing observer failed\n");
		return 1;
	}

	struct vmpressure_bpf *skel = vmpressure_bpf__open();
	if (!skel) {
		fprintf(stderr, "open skeleton failed\n");
		return 1;
	}
	if (vmpressure_bpf__load(skel)) {
		fprintf(stderr, "load failed\n");
		vmpressure_bpf__destroy(skel);
		return 1;
	}
	if (vmpressure_bpf__attach(skel)) {
		fprintf(stderr, "attach failed\n");
		vmpressure_bpf__destroy(skel);
		return 1;
	}

	struct ring_buffer *rb =
	    ring_buffer__new(bpf_map__fd(skel->maps.events),
			     handle_event, observer, NULL);
	if (!rb) {
		fprintf(stderr, "ring_buffer__new: %s\n", strerror(errno));
		vmpressure_bpf__destroy(skel);
		vmpressure_observer_fini(observer);
		return 1;
	}

	int rb_fd = ring_buffer__epoll_fd(rb);
	if (rb_fd < 0)
	{
		fprintf(stderr, "ring_buffer__epoll_fd: %s\n", strerror(errno));
		ring_buffer__free(rb);
		vmpressure_bpf__destroy(skel);
		vmpressure_observer_fini(observer);
		return 1;
	}

	int ep_fd = epoll_create1(EPOLL_CLOEXEC);
	if (ep_fd < 0)
	{
		fprintf(stderr, "epoll_create1: %s\n", strerror(errno));
		ring_buffer__free(rb);
		vmpressure_bpf__destroy(skel);
		vmpressure_observer_fini(observer);
		return 1;
	}

	struct epoll_event ev_ringbuf = {
		.events = EPOLLIN,
		.data.u32 = FD_RINGBUF,
	};

	if (epoll_ctl(ep_fd, EPOLL_CTL_ADD, rb_fd, &ev_ringbuf) < 0)
	{
		fprintf(stderr, "epoll_ctl ringbuf: %s\n", strerror(errno));

		ring_buffer__free(rb);
		vmpressure_bpf__destroy(skel);
		vmpressure_observer_fini(observer);
	}

	int tfd = make_timerfd();
	struct epoll_event ev_timerfd = {
		.events = EPOLLIN,
		.data.u32 = FD_TIMERFD,
	};

	if (epoll_ctl(ep_fd, EPOLL_CTL_ADD, tfd, &ev_timerfd) < 0)
	{
		fprintf(stderr, "epoll_ctl timerfd: %s\n", strerror(errno));

		ring_buffer__free(rb);
		vmpressure_bpf__destroy(skel);
		vmpressure_observer_fini(observer);
	}

	while (!stop) {
		struct epoll_event events[8];

		int n = epoll_wait(ep_fd, events, 8, -1);
		if (n < 0)
		{
			if (errno == EINTR)
				continue;

			fprintf(stderr, "epoll_wait: %s\n", strerror(errno));
			break;
		}

		for (int i = 0; i < n; i++)
		{
			switch (events[i].data.u32)
			{
				case FD_RINGBUF:
					int r = ring_buffer__poll(rb, 0);
					if (r < 0)
						fprintf(stderr, "process ringbuf: %s\n", strerror(errno));
					break;

				case FD_TIMERFD:
					uint64_t expirations;
					read(tfd, &expirations, sizeof(expirations));
					vmpressure_observer_tick(observer, now_nsec());
					break;

				default:
					break;
			}
		}

		fprintf(stderr, "[%lld] CURRENT=%s\n",
			(long long) now_nsec(),
			stnames[vmpressure_observer_state(observer)]);
	}

	ring_buffer__free(rb);
	vmpressure_bpf__destroy(skel);
	vmpressure_observer_fini(observer);

	return 0;
}
