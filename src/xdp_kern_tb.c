// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/*
 * Copyright (C) 2021-2026 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 *
 * Skeleton for XDP eBPF filter. Define EBPF_VID, EBPF_ETH_TYPE and EBPF_PRIORITY.  Set
 * EBPF_CHECK_FRAMEID for Profinet when compiling.
 */

#include <stdbool.h>

#include <linux/bpf.h>
#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include <xdp/xdp_helpers.h>

#include "net_def.h"
#include "xdp_metadata.c"

#ifndef EBPF_VID
#error "Please compile this with -DEBPF_VID=<VLAN>"
#endif

#ifndef EBPF_ETH_TYPE
#error "Please compile this with -DEBPF_ETH_TYPE=<EtherType>"
#endif

#ifndef EBPF_PRIORITY
#error "Please compile this with -DEBPF_PRIORITY=<priority>"
#endif

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(max_entries, 128);
} xsks_map SEC(".maps");

struct {
	__uint(priority, EBPF_PRIORITY);
	__uint(XDP_PASS, 1);
} XDP_RUN_CONFIG(xdp_sock_prog);

#ifdef EBPF_CHECK_FRAMEID
static __always_inline bool check_frame_id(struct profinet_rt_header *rt)
{
	__u16 frame_id;

	frame_id = bpf_ntohs(rt->frame_id);
	switch (frame_id) {
	case TSN_HIGH_FRAMEID:
	case TSN_HIGH_SEC_FRAMEID:
	case TSN_LOW_FRAMEID:
	case TSN_LOW_SEC_FRAMEID:
	case RTC_FRAMEID:
	case RTC_SEC_FRAMEID:
	case RTA_FRAMEID:
	case RTA_SEC_FRAMEID:
		return true;
	default:
		return false;
	}
}
#endif

SEC("xdp_sock")
int xdp_sock_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct vlan_ethernet_header *veth;
	int idx = ctx->rx_queue_index;
	void *p = data;

	veth = p;
	if ((void *)(veth + 1) > data_end)
		return XDP_PASS;
	p += sizeof(*veth);

	if (veth->vlan_proto != bpf_htons(ETH_P_8021Q))
		return XDP_PASS;

	if (veth->vlan_encapsulated_proto != bpf_htons(EBPF_ETH_TYPE))
		return XDP_PASS;

	if ((bpf_ntohs(veth->vlantci) & VLAN_ID_MASK) != EBPF_VID)
		return XDP_PASS;

#ifdef EBPF_CHECK_FRAMEID
	struct profinet_rt_header *rt = p;

	if ((void *)(rt + 1) > data_end)
		return XDP_PASS;

	if (!check_frame_id(rt))
		return XDP_PASS;
#endif

	if (bpf_map_lookup_elem(&xsks_map, &idx)) {
		populate_rx_timestamp(ctx);
		return bpf_redirect_map(&xsks_map, idx, 0);
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "Dual BSD/GPL";
