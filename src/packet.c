// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2024-2025 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <linux/if_packet.h>

#include "log.h"
#include "packet.h"
#include "thread.h"
#include "tx_time.h"
#include "utils.h"

struct packet_context *packet_init(size_t num_frames_per_cycle)
{
	struct packet_context *context;

	context = calloc(1, sizeof(*context));
	if (!context) {
		fprintf(stderr, "Failed to allocate packet context!\n");
		return NULL;
	}

	context->rx_frames = calloc(MAX_FRAME_SIZE * num_frames_per_cycle, sizeof(unsigned char));
	if (!context->rx_frames) {
		fprintf(stderr, "Failed to allocate receive frame buffers!\n");
		goto err_rx_frames;
	}

	context->rx_iovecs = calloc(num_frames_per_cycle, sizeof(*context->rx_iovecs));
	if (!context->rx_iovecs) {
		fprintf(stderr, "Failed to allocate receive io vectors!\n");
		goto err_rx_iovecs;
	}

	context->rx_msgs = calloc(num_frames_per_cycle, sizeof(*context->rx_msgs));
	if (!context->rx_msgs) {
		fprintf(stderr, "Failed to allocate receive messages!\n");
		goto err_rx_msgs;
	}

	context->tx_iovecs = calloc(num_frames_per_cycle, sizeof(*context->tx_iovecs));
	if (!context->tx_iovecs) {
		fprintf(stderr, "Failed to allocate transmit io vectors!\n");
		goto err_tx_iovecs;
	}

	context->tx_msgs = calloc(num_frames_per_cycle, sizeof(*context->tx_msgs));
	if (!context->tx_msgs) {
		fprintf(stderr, "Failed to allocate transmit messages!\n");
		goto err_tx_msgs;
	}

	context->tx_control_msgs = calloc(num_frames_per_cycle, sizeof(*context->tx_control_msgs));
	if (!context->tx_control_msgs) {
		fprintf(stderr, "Failed to allocated transmit control messages!\n");
		goto err_tx_ctrl_msgs;
	}

	context->num_frames_per_cycle = num_frames_per_cycle;

	return context;

err_tx_ctrl_msgs:
	free(context->tx_msgs);
err_tx_msgs:
	free(context->tx_iovecs);
err_tx_iovecs:
	free(context->rx_msgs);
err_rx_msgs:
	free(context->rx_iovecs);
err_rx_iovecs:
	free(context->rx_frames);
err_rx_frames:
	free(context);

	return NULL;
}

void packet_free(struct packet_context *context)
{
	if (!context)
		return;

	free(context->rx_frames);
	free(context->rx_iovecs);
	free(context->tx_iovecs);
	free(context->rx_msgs);
	free(context->tx_msgs);
	free(context->tx_control_msgs);
	free(context);
}

int packet_send_messages(struct packet_context *context, struct packet_send_request *send_req)
{
	int sent = 0;

	/*
	 * It is expected to sent exactly num_frames_per_cycle. However, in case frames arrived late
	 * or were dropped the number might be different.
	 */
	while (sent < send_req->num_frames) {
		struct iovec *iovecs = context->tx_iovecs;
		struct mmsghdr *msgs = context->tx_msgs;
		int i, inner_sent = 0, to_be_sent;

		to_be_sent = send_req->num_frames - sent;
		if (to_be_sent > context->num_frames_per_cycle)
			to_be_sent = context->num_frames_per_cycle;

		for (i = 0; i < to_be_sent; i++) {
			unsigned char *frame;
			int idx;

			idx = sent + i;
			frame = send_req->mirror_enabled
					? send_req->frame_data + idx * send_req->frame_length
					: frame_idx(send_req->frame_data, idx);
			iovecs[i].iov_base = frame;
			iovecs[i].iov_len = send_req->frame_length;
			msgs[i].msg_hdr.msg_iov = &iovecs[i];
			msgs[i].msg_hdr.msg_iovlen = 1;
			msgs[i].msg_hdr.msg_name = send_req->destination;
			msgs[i].msg_hdr.msg_namelen = sizeof(*send_req->destination);

			/* In case the user configured Tx Time also add it. */
			if (send_req->tx_time_enabled) {
				unsigned char *control = context->tx_control_msgs[i].control;
				uint64_t tx_time, sequence_counter;
				struct cmsghdr *cmsg;

				sequence_counter =
					get_sequence_counter(frame, send_req->meta_data_offset,
							     context->num_frames_per_cycle);

				tx_time = tx_time_get_frame_tx_time(
					sequence_counter, send_req->duration,
					context->num_frames_per_cycle, send_req->tx_time_offset,
					send_req->traffic_class);

				msgs[i].msg_hdr.msg_control = control;
				msgs[i].msg_hdr.msg_controllen = sizeof(*context->tx_control_msgs);

				cmsg = CMSG_FIRSTHDR(&msgs[i].msg_hdr);
				cmsg->cmsg_level = SOL_SOCKET;
				cmsg->cmsg_type = SO_TXTIME;
				cmsg->cmsg_len = CMSG_LEN(sizeof(int64_t));
				*((uint64_t *)CMSG_DATA(cmsg)) = tx_time;
			}
		}

		/* Send them. */
		while (inner_sent < to_be_sent) {
			int len;

			len = sendmmsg(send_req->socket_fd, &msgs[inner_sent],
				       to_be_sent - inner_sent, 0);
			if (len == -1) {
				log_message(LOG_LEVEL_ERROR, "%sTx: sendmmsg() failed: %s\n",
					    send_req->traffic_class, strerror(errno));
				return -errno;
			}

			inner_sent += len;
		}

		sent += inner_sent;
	}

	return sent;
}

int packet_receive_messages(struct packet_context *context, struct packet_receive_request *recv_req)
{
	int received = 0;

	while (true) {
		struct iovec *iovecs = context->rx_iovecs;
		struct mmsghdr *msgs = context->rx_msgs;
		int i, len;

		for (i = 0; i < context->num_frames_per_cycle; i++) {
			iovecs[i].iov_base = frame_idx(context->rx_frames, i);
			iovecs[i].iov_len = MAX_FRAME_SIZE;
			msgs[i].msg_hdr.msg_iov = &iovecs[i];
			msgs[i].msg_hdr.msg_iovlen = 1;
		}

		len = recvmmsg(recv_req->socket_fd, msgs, context->num_frames_per_cycle, 0, NULL);
		if (len == -1) {
			/* No more frames. Come back within next period. */
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;

			log_message(LOG_LEVEL_ERROR, "%sRx: recvmmsg() failed: %s\n",
				    recv_req->traffic_class, strerror(errno));
			break;
		}

		/* Process received frames. */
		for (i = 0; i < len; i++)
			recv_req->receive_function(recv_req->data, frame_idx(context->rx_frames, i),
						   msgs[i].msg_len);

		received += len;
	}

	return received;
}
