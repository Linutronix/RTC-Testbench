/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2026 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#ifndef TC_H
#define TC_H

#include "utils.h"

enum tc_tx_model {
	TC_TX_CYCLIC,     /* TSN, RTC */
	TC_TX_BURST,      /* RTA, DCP, UDP, LLDP */
	TC_TX_STANDALONE, /* L2 */
};

enum tc_tx_wait_result {
	TC_TX_WAIT_SEND,  /* Cycle triggered, send frames */
	TC_TX_WAIT_STOP,  /* Signal missing, check stop */
	TC_TX_WAIT_ERROR, /* Fatal, stop thread */
};

struct thread_context;

struct traffic_class_ops {
	/* Initialize frame */
	void (*initialize_frame)(struct thread_context *ctx, unsigned char *frame_data,
				 size_t frame_length, const unsigned char *source,
				 const unsigned char *destination);

	/* Receive frame callback */
	int (*receive_frame)(void *data, unsigned char *frame_data, size_t len);

	/* Raw socket creation function */
	int (*create_socket)(void);

	/* Tx/Rx thread depending on socket type: AF_PACKET or AF_XDP */
	void *(*tx_thread)(void *data);
	void *(*rx_thread)(void *data);
};

struct traffic_class_desc {
	struct traffic_class_ops ops;
	enum tc_tx_model tx_model;
};

int tc_threads_create(struct thread_context *ctx);
void *tc_tx_thread(void *data);
void *tc_rx_thread(void *data);
void *tc_xdp_tx_thread(void *data);
void *tc_xdp_rx_thread(void *data);
int tc_sleep_until(const struct thread_context *ctx, struct timespec *wakeup, uint64_t cycle_time);
int tc_wait_for_tx(struct thread_context *ctx);
int tc_wait_for_tx_burst(struct thread_context *ctx, size_t *num_frames);
void tc_signal_next(struct thread_context *ctx);
void *tc_tx_gen_thread(void *data);
void tc_threads_wait_for_finish(struct thread_context *ctx);
void tc_threads_free(struct thread_context *ctx);

#endif /* TC_H */
