// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
/* Adapted by yanniszark in 2024 */

// All linux kernel type definitions are in vmlinux.h
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "iolatency.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_ENTRIES 15555

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct request *);
    __type(value, u64);
} start SEC(".maps");

// Define map for histogram
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct hist);
} hist SEC(".maps");

static struct hist hist0;

SEC("raw_tracepoint/block_rq_insert")
int BPF_PROG(block_rq_insert, struct request *rq) {
    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start, &rq, &ts, BPF_ANY);
    return 0;
}

SEC("raw_tracepoint/block_rq_issue")
int BPF_PROG(block_rq_issue, struct request *rq) {
    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start, &rq, &ts, BPF_ANY);
    return 0;
}

static __always_inline u64 log2(u32 v) {
	u32 shift, r;

	r = (v > 0xFFFF) << 4; v >>= r;
	shift = (v > 0xFF) << 3; v >>= shift; r |= shift;
	shift = (v > 0xF) << 2; v >>= shift; r |= shift;
	shift = (v > 0x3) << 1; v >>= shift; r |= shift;
	r |= (v >> 1);

	return r;
}

static __always_inline u64 log2l(u64 v) {
	u32 hi = v >> 32;

	if (hi)
		return log2(hi) + 32;
	else
		return log2(v);
}

SEC("raw_tracepoint/block_rq_complete")
int BPF_PROG(block_rq_complete, struct request *rq) {
    u64 *tsp;
    u64 slot;
    s64 delta;
    struct hist *h;
    u64 ts = bpf_ktime_get_ns();

    tsp = bpf_map_lookup_elem(&start, &rq);

    if (!tsp)
        return 0;

    delta = (s64)(ts - *tsp);
    bpf_map_delete_elem(&start, &rq);

    if (delta < 0)
        return 0;

    // Get histogram from map
    u32 zero = 0;
    h = bpf_map_lookup_elem(&hist, &zero);
    if (!h) {
        bpf_map_update_elem(&hist, &zero, &hist0, BPF_ANY);
        h = bpf_map_lookup_elem(&hist, &zero);
        if (!h)
            return 0;
    }

    // Microseconds
    delta /= 1000U;

    slot = log2l(delta);
    if (slot >= SLOTS)
        slot = SLOTS - 1;

    // Update histogram
    __sync_fetch_and_add(&h->slots[slot], 1);

    return 0;
}

