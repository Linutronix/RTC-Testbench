// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2020-2024 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ring_buffer.h"
#include "thread.h"

struct ring_buffer *ring_buffer_allocate(size_t buffer_size)
{
	struct ring_buffer *ring_buffer;

	ring_buffer = calloc(1, sizeof(*ring_buffer));
	if (!ring_buffer)
		return NULL;

	ring_buffer->data = calloc(buffer_size, sizeof(unsigned char));
	if (!ring_buffer->data) {
		free(ring_buffer);
		return NULL;
	}

	ring_buffer->buffer_size = buffer_size;
	ring_buffer->buffer_write_pointer = ring_buffer->data;
	ring_buffer->buffer_read_pointer = ring_buffer->data;

	init_mutex(&ring_buffer->data_mutex);

	return ring_buffer;
}

void ring_buffer_free(struct ring_buffer *ring_buffer)
{
	if (!ring_buffer)
		return;

	free(ring_buffer->data);
	free(ring_buffer);
}

void ring_buffer_add(struct ring_buffer *ring_buffer, const unsigned char *data, size_t len)
{
	size_t available;

	if (!ring_buffer)
		return;

	if (len > ring_buffer->buffer_size)
		return;

	pthread_mutex_lock(&ring_buffer->data_mutex);

	/* Wrap? */
	available =
		(ring_buffer->data + ring_buffer->buffer_size) - ring_buffer->buffer_write_pointer;
	if (len <= available) {
		memcpy(ring_buffer->buffer_write_pointer, data, len);
		ring_buffer->buffer_write_pointer += len;
	} else {
		memcpy(ring_buffer->buffer_write_pointer, data, available);
		len -= available;
		data += available;
		ring_buffer->buffer_write_pointer = ring_buffer->data;
		memcpy(ring_buffer->buffer_write_pointer, data, len);
		ring_buffer->buffer_write_pointer += len;
	}

	if ((ring_buffer->data + ring_buffer->buffer_size) == ring_buffer->buffer_write_pointer)
		ring_buffer->buffer_write_pointer = ring_buffer->data;

	pthread_mutex_unlock(&ring_buffer->data_mutex);
}

void ring_buffer_fetch(struct ring_buffer *ring_buffer, unsigned char *data, size_t len,
		       size_t *out_len)
{
	intptr_t available;
	size_t real_len;

	if (!ring_buffer)
		return;

	if (len > ring_buffer->buffer_size)
		return;

	pthread_mutex_lock(&ring_buffer->data_mutex);

	available = ring_buffer->buffer_write_pointer - ring_buffer->buffer_read_pointer;

	/* Simple case: Copy difference between read and write ptr. */
	if (available > 0) {
		real_len = available > len ? len : available;
		memcpy(data, ring_buffer->buffer_read_pointer, real_len);
		*out_len = real_len;
		ring_buffer->buffer_read_pointer += real_len;
	} else if (available < 0) {
		/* Copy first part */
		available = (ring_buffer->data + ring_buffer->buffer_size) -
			    ring_buffer->buffer_read_pointer;
		real_len = available > len ? len : available;
		memcpy(data, ring_buffer->buffer_read_pointer, real_len);

		len -= real_len;
		data += real_len;
		*out_len = real_len;
		ring_buffer->buffer_read_pointer += real_len;

		if (ring_buffer->buffer_read_pointer ==
		    (ring_buffer->data + ring_buffer->buffer_size))
			ring_buffer->buffer_read_pointer = ring_buffer->data;

		/* Copy second part */
		if (len > 0) {
			available = ring_buffer->buffer_write_pointer -
				    ring_buffer->buffer_read_pointer;
			real_len = available > len ? len : available;

			memcpy(data, ring_buffer->buffer_read_pointer, real_len);

			ring_buffer->buffer_read_pointer += real_len;
			*out_len += real_len;
		}
	} else {
		*out_len = 0;
	}

	if (ring_buffer->buffer_read_pointer == (ring_buffer->data + ring_buffer->buffer_size))
		ring_buffer->buffer_read_pointer = ring_buffer->data;

	pthread_mutex_unlock(&ring_buffer->data_mutex);
}
