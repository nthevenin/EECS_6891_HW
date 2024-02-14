#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "iolatency.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

#define min(x, y) ({				\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	(void) (&_min1 == &_min2);		\
	_min1 < _min2 ? _min1 : _min2; })


static void out_stars(unsigned int val, unsigned int val_max, int width) {
	int num_stars, num_spaces, i;
	bool plus;

	num_stars = min(val, val_max) * width / val_max;
	num_spaces = width - num_stars;
	plus = val > val_max;

	for (i = 0; i < num_stars; i++)
		printf("*");
	for (i = 0; i < num_spaces; i++)
		printf(" ");
	if (plus)
		printf("+");
}

void print_hist(unsigned int *vals, int vals_size, const char *val_type) {
	int stars_max = 40, idx_max = -1;
	unsigned int val, val_max = 0;
	unsigned long long low, high;
	int stars, width, i;

	for (i = 0; i < vals_size; i++) {
		val = vals[i];
		if (val > 0)
			idx_max = i;
		if (val > val_max)
			val_max = val;
	}

	if (idx_max < 0)
		return;

	printf("%*s%-*s : count  distribution\n", idx_max <= 32 ? 5 : 15, "",
		idx_max <= 32 ? 19 : 29, val_type);

	if (idx_max <= 32)
		stars = stars_max;
	else
		stars = stars_max / 2;

	for (i = 0; i <= idx_max; i++) {
		low = (1ULL << (i + 1)) >> 1;
		high = (1ULL << (i + 1)) - 1;
		if (low == high)
			low -= 1;
		val = vals[i];
		width = idx_max <= 32 ? 10 : 20;
		printf("%*lld -> %-*lld : %-8d |", width, low, width, high, val);
		out_stars(val, val_max, stars);
		printf("|\n");
	}
}

int main(int argc, char **argv) {

    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *ltinks[3];
    int prog_fd;
    int interval;

    //Inputs
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interval>\n", argv[0]);
        return 1;
    }

    interval = atoi(argv[1]);

    // Load and verify BPF application
    fprintf(stderr, "Loading BPF code in memory\n");
    obj = bpf_object__open_file("iolatency.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        return 1;
    }

    // Load BPF program
    fprintf(stderr, "Loading and verifying the code in the kernel\n");
    if (bpf_object__load(obj)) {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        return 1;
    }

    // Load histogram maps in BPF
    struct bpf_map *histmap;
    histmap = bpf_object__find_map_by_name(obj, "hist");
    if (libbpf_get_error(histmap)) {
        fprintf(stderr, "ERROR: loading BPF map failed\n");
        return 1;
    }

    int map_fd = bpf_map__fd(histmap);
    
    struct hist hist0 = {0};
    __u32 key = 0;
    if (bpf_map_update_elem(map_fd, &key, &hist0, BPF_ANY) < 0) {
        perror("bpf_map_update_elem");
        return 1;
    }

    // Attach BPF program
    char *prog_names[] = {"block_rq_insert", "block_rq_issue", "block_rq_complete",};

    struct bpf_link *links[ARRAY_SIZE(prog_names)];

    for (int i = 0; i < ARRAY_SIZE(prog_names); i++) {
        prog = bpf_object__find_program_by_name(obj, prog_names[i]);
        if (libbpf_get_error(prog)) {
            fprintf(stderr, "ERROR: finding BPF program failed\n");
            return 1;
        }
        prog_fd = bpf_program__fd(prog);
        if (prog_fd < 0) {
            fprintf(stderr, "ERROR: getting BPF program FD failed\n");
            return 1;
        }

        links[i] = bpf_program__attach(prog);
        if (libbpf_get_error(links[i])) {
            fprintf(stderr, "ERROR: Attaching BPF program failed\n");
            return 1;
        }
    }
    printf("Tracepoint attached with neeeded maps. Printing histogram..");

    while (1) {
        sleep(interval);

        // Get histogram
        struct hist hist;
        if (bpf_map_lookup_elem(map_fd, &key, &hist) < 0) {
            perror("bpf_map_lookup_elem");
            break;
        }

        // Reset
        if (bpf_map_update_elem(map_fd, &key, &hist0, BPF_ANY) < 0) {
            perror("bpf_map_update_elem");
            break;
        }

        // Print out histogram
        print_hist(hist.slots, SLOTS, " usecs");
        printf("\n");
    }

    // Cleanup
    for (int i = 0; i < ARRAY_SIZE(links); i++) {
        bpf_link__destroy(links[i]);
    }
    bpf_object__close(obj);

    return 0;
}

