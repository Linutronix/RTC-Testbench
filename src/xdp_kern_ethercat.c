// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/*
 * Copyright (C) 2021,2022 Linutronix GmbH
 * Author Haithem Jebali <h.jebali@acontis.com>
 */

#include <linux/bpf.h>
#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include <xdp/xdp_helpers.h>

#include "net_def.h"
#include "xdp_metadata.c"

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(max_entries, 128);
} xsks_map SEC(".maps");

struct {
	__uint(priority, 10);
	__uint(XDP_PASS, 1);
} XDP_RUN_CONFIG(xdp_sock_prog);

SEC("xdp_sock")
int xdp_sock_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth;
	int idx = ctx->rx_queue_index;
	void *p = data;

	eth = p;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;
	p += sizeof(*eth);

	/* Check for valid EtherCAT frames */
	if (eth->h_proto != bpf_htons(ETH_P_ETHERCAT))
		return XDP_PASS;

	/* If socket bound to rx_queue then redirect to user space */
	if (bpf_map_lookup_elem(&xsks_map, &idx)) {
		populate_rx_timestamp(ctx);
		return bpf_redirect_map(&xsks_map, idx, 0);
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "Dual BSD/GPL";
