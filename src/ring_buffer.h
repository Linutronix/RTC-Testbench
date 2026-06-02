/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2020-2026 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#ifndef _RING_BUFFER_H_
#define _RING_BUFFER_H_

#include <pthread.h>

/*
 * There is the need for concurrent circular buffers with this code e.g. for:
 *  a) Packet/Frame buffering
 *  b) Logging
 *
 * Introduce a "generic" ring buffer suitable for both scenarios.
 *
 * The policy is drop oldest data first and keep the newest. The functions will not block. Old data
 * is overwritten without any warning.
 *
 * The locking is done with PI mutex. This is fine for the Ethernet frame data, because there's no
 * lock contention (Tx and Rx run at different time slots). However, in case of logging lots of
 * messages, there might be contention. FIXME: To get rid of this, implement per traffic class
 * logging.
 */
struct ring_buffer {
	size_t buffer_size;
	unsigned char *buffer_write_pointer;
	unsigned char *buffer_read_pointer;
	unsigned char *data;
	pthread_mutex_t data_mutex;
};

struct ring_buffer *ring_buffer_allocate(size_t buffer_size);
void ring_buffer_add(struct ring_buffer *ring_buffer, const unsigned char *data, size_t len);
void ring_buffer_fetch(struct ring_buffer *ring_buffer, unsigned char *data, size_t len,
		       size_t *out_len);
void ring_buffer_free(struct ring_buffer *ring_buffer);

#endif /* _RING_BUFFER_H_ */
