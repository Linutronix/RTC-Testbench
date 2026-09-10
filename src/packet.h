/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2024-2025 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#ifndef PACKET_H
#define PACKET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <linux/errqueue.h>
#include <sys/socket.h>

#include "stat.h"

struct tx_control_msg {
	unsigned char control[CMSG_SPACE(sizeof(uint64_t)) + CMSG_SPACE(sizeof(unsigned int))];
} __attribute((packed));

struct rx_control_msg {
	unsigned char control[CMSG_SPACE(sizeof(struct scm_timestamping))];
} __attribute((packed));

/*
 * Sized for both the SCM_TIMESTAMPING cmsg and the SO_EE_ORIGIN_TIMESTAMPING error cmsg
 * that comes with it on MSG_ERRQUEUE completions.
 */
struct tx_completion_control_msg {
	unsigned char control[CMSG_SPACE(sizeof(struct sock_extended_err) +
					 sizeof(struct sockaddr_storage)) +
			      CMSG_SPACE(sizeof(struct scm_timestamping))];
} __attribute((packed));

struct packet_context {
	unsigned char *rx_frames;
	struct iovec *rx_iovecs;
	struct iovec *tx_iovecs;
	struct mmsghdr *rx_msgs;
	struct mmsghdr *tx_msgs;
	struct tx_control_msg *tx_control_msgs;
	struct rx_control_msg *rx_control_msgs;
	unsigned char *tx_completion_frame;
	struct tx_completion_control_msg tx_completion_control;
	size_t num_frames_per_cycle;
};

struct packet_context *packet_init(size_t num_frames_per_cycle);
void packet_free(struct packet_context *context);

struct packet_send_request {
	const char *traffic_class;
	int socket_fd;
	struct sockaddr_ll *destination;
	unsigned char *frame_data;
	size_t num_frames;
	size_t frame_length;
	uint64_t duration;
	uint64_t tx_time_offset;
	uint32_t meta_data_offset;
	bool mirror_enabled;
	bool tx_time_enabled;
	bool tx_hwtstamp_enabled;
};

int packet_send_messages(struct packet_context *context, struct packet_send_request *send_req);

struct packet_receive_request {
	const char *traffic_class;
	int socket_fd;
	int (*receive_function)(void *data, unsigned char *, size_t);
	void *data;
	bool rx_hwtstamp_enabled;
};

int packet_receive_messages(struct packet_context *context,
			    struct packet_receive_request *recv_req);

/* Retrieve RX HW/SW timestamps stashed by packet_receive_messages() for this frame. */
void packet_get_timestamp_metadata(void *data, uint64_t *rx_hw_ts, uint64_t *rx_sw_ts);

struct packet_tx_completion_request {
	const char *traffic_class;
	int socket_fd;
	enum stat_frame_type frame_type;
	uint32_t meta_data_offset;
	size_t num_frames_per_cycle;
};

/* Drains pending TX HW timestamp completions from the error queue; no-op without TX_TIMESTAMP. */
void packet_process_tx_completions(struct packet_context *context,
				   const struct packet_tx_completion_request *req);

#endif /* PACKET_H */
