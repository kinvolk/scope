typedef void (*print_fn)(void *data, int size);

struct perf_event_sample {
	struct perf_event_header header;
	__u32 size;
	char data[];
};

void perf_event_read(volatile struct perf_event_mmap_page *header, print_fn fn);
void print_bpf_output(void *data, int size);
