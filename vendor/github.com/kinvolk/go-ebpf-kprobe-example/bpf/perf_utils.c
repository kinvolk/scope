#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <linux/perf_event.h>
#include "libbpf.h"
#include "perf_utils.h"

void perf_event_read(volatile struct perf_event_mmap_page *header, print_fn fn)
{
	int page_size;
	page_size = getpagesize();

	__u64 data_tail = header->data_tail;
	__u64 data_head = header->data_head;
	__u64 buffer_size = PAGE_COUNT * page_size;
	void *base, *begin, *end;
	char buf[256];

	asm volatile("" ::: "memory"); // in real code it should be smp_rmb()
	if (data_head == data_tail)
		return;

	base = ((char *)header) + page_size;

	begin = base + data_tail % buffer_size;
	end = base + data_head % buffer_size;

	while (begin != end) {
		struct perf_event_sample *e;

		e = begin;
		if (begin + e->header.size > base + buffer_size) {
			long len = base + buffer_size - begin;

			assert(len < e->header.size);
			memcpy(buf, begin, len);
			memcpy(buf + len, base, e->header.size - len);
			e = (void *) buf;
			begin = base + e->header.size - len;
		} else if (begin + e->header.size == base + buffer_size) {
			begin = base;
		} else {
			begin += e->header.size;
		}

		if (e->header.type == PERF_RECORD_SAMPLE) {
			fn(e->data, e->size);
		} else if (e->header.type == PERF_RECORD_LOST) {
			struct {
				struct perf_event_header header;
				__u64 id;
				__u64 lost;
			} *lost = (void *) e;
			printf("lost %lld events\n", lost->lost);
		} else {
			printf("unknown event type=%d size=%d\n",
			       e->header.type, e->header.size);
		}
	}

	__sync_synchronize(); /* smp_mb() */
	header->data_tail = data_head;
}
