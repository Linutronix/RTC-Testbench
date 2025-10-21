/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2021-2025 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#ifndef _XDP_H_
#define _XDP_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <linux/if_xdp.h>

#include "app_config.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <xdp/libxdp.h>
#include <xdp/xsk.h>

#include "security.h"
#include "stat.h"

#undef XSK_RING_CONS__DEFAULT_NUM_DESCS
#undef XSK_RING_PROD__DEFAULT_NUM_DESCS
#define XSK_RING_CONS__DEFAULT_NUM_DESCS 4096
#define XSK_RING_PROD__DEFAULT_NUM_DESCS 4096

#define XDP_BATCH_SIZE 512
#define XDP_NUM_FRAMES (XSK_RING_CONS__DEFAULT_NUM_DESCS + XSK_RING_PROD__DEFAULT_NUM_DESCS)
#define XDP_FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE

struct xsk_umem_info {
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_umem *umem;
	void *buffer;
};

struct xdp_tx_hwts {
	/* Store HW timestamps from AF_XDP completion queue */
	struct round_trip_context *rtt;
	/* Sequence number for TX HW timestamp (available one cycle later) */
	int64_t seq_lagged;
	/* Counter for tracking TX HW timestamp completions in current cycle (max 2: first+last) */
	uint32_t count;
	/* Total number of frames per cycle (needed to identify last packet) */
	uint32_t frames_per_cycle;
};

struct xdp_socket {
	uint64_t outstanding_tx;
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_umem_info umem;
	struct xsk_socket *xsk;
	struct xdp_program *prog;
	/* TX hardware timestamping context */
	struct xdp_tx_hwts tx_hwts;
	int fd;
	bool busy_poll_mode;
	bool tx_time_mode;
	bool tx_hwtstamp_mode;
};

struct xdp_tx_time {
	const char *traffic_class;
	uint64_t sequence_counter_begin;
	uint64_t duration;
	uint64_t tx_time_offset;
	size_t num_frames_per_cycle;
};

struct xdp_gen_config {
	enum security_mode mode;
	struct security_context *security_context;
	const unsigned char *iv_prefix;
	const unsigned char *payload_pattern;
	size_t payload_pattern_length;
	size_t frame_length;
	size_t num_frames_per_cycle;
	uint32_t *frame_number;
	uint64_t sequence_counter_begin;
	uint32_t meta_data_offset;
	enum stat_frame_type frame_type;
	const struct xdp_tx_time *tx_time;
};

struct xdp_socket *xdp_open_socket(const char *interface, const char *xdp_program, int queue,
				   bool skb_mode, bool zero_copy_mode, bool wakeup_mode,
				   bool busy_poll_mode, bool tx_time_mode, bool tx_hwtstamp_mode);
void xdp_close_socket(struct xdp_socket *xsk, const char *interface, bool skb_mode);
void xdp_complete_tx_only(struct xdp_socket *xsk);
void xdp_complete_tx(struct xdp_socket *xsk);
void xdp_gen_and_send_frames(struct xdp_socket *xsk, const struct xdp_gen_config *xdp);
unsigned int xdp_receive_frames(struct xdp_socket *xsk, size_t frame_length, bool mirror_enabled,
				int (*receive_function)(void *data, unsigned char *, size_t),
				void *data, const struct xdp_tx_time *tx_time);
void xdp_get_timestamp_metadata(void *data, uint64_t *rx_hw_ts, uint64_t *rx_sw_ts);

#endif /* _XDP_H_ */
