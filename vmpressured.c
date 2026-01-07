#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>

#include "vmpressure.h"
#include "vmpressure.skel.h"

static volatile sig_atomic_t stop;

static void sigint_handler(int signo)
{
	(void) signo;
	stop = 1;
}

static const char *evname(__u32 t)
{
	switch (t) {
	case 1:
		return "KSWAPD_WAKE";
	case 2:
		return "DIRECT_RECLAIM_BEGIN";
	case 3:
		return "BALANCE_PGDAT";
	default:
		return "UNKNOWN";
	}
}

static long pages_to_kb(long pages)
{
	if (pages < 0)
		return -1;
	long ps = sysconf(_SC_PAGESIZE);
	return (pages * ps) / 1024;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	(void) ctx;
	(void) data_sz;
	const struct event *e = data;

	printf
	    ("[%s] cpu=%u nid=%u order=%u  free=%ldkB file=%ldkB anon=%ldkB shmem=%ldkB",
	     evname(e->type), e->cpu, e->nid, e->order,
	     pages_to_kb(e->nr_free_pages), pages_to_kb(e->nr_file_pages),
	     pages_to_kb(e->nr_anon_mapped), pages_to_kb(e->nr_shmem));

	if (e->nr_slab_reclaimable >= 0)
		printf(" slab_recl=%ldkB",
		       pages_to_kb(e->nr_slab_reclaimable));
	if (e->nr_slab_unreclaimable >= 0)
		printf(" slab_unrecl=%ldkB",
		       pages_to_kb(e->nr_slab_unreclaimable));

	printf("\n");
	return 0;
}

int main(void)
{
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

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
			     handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "ring_buffer__new: %s\n", strerror(errno));
		vmpressure_bpf__destroy(skel);
		return 1;
	}

	while (!stop) {
		int err = ring_buffer__poll(rb, 500);
		if (err == -EINTR)
			break;
		if (err < 0) {
			fprintf(stderr, "poll: %d\n", err);
			break;
		}
	}

	ring_buffer__free(rb);
	vmpressure_bpf__destroy(skel);
	return 0;
}
