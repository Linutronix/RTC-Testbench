// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2020-2026 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ring_buffer.h"
#include "thread.h"

struct ring_buffer *ring_buffer_allocate(size_t size)
{
	struct ring_buffer *rb;

	rb = calloc(1, sizeof(*rb));
	if (!rb)
		return NULL;

	rb->data = calloc(size, sizeof(unsigned char));
	if (!rb->data) {
		free(rb);
		return NULL;
	}

	rb->size = size;
	rb->wp = rb->data;
	rb->rp = rb->data;

	init_mutex(&rb->mutex);

	return rb;
}

void ring_buffer_free(struct ring_buffer *rb)
{
	if (!rb)
		return;

	free(rb->data);
	free(rb);
}

void ring_buffer_add(struct ring_buffer *rb, const unsigned char *data, size_t len)
{
	size_t available;

	if (!rb)
		return;

	if (len > rb->size)
		return;

	pthread_mutex_lock(&rb->mutex);

	/* Wrap? */
	available = (rb->data + rb->size) - rb->wp;
	if (len <= available) {
		memcpy(rb->wp, data, len);
		rb->wp += len;
	} else {
		memcpy(rb->wp, data, available);
		len -= available;
		data += available;
		rb->wp = rb->data;
		memcpy(rb->wp, data, len);
		rb->wp += len;
	}

	if ((rb->data + rb->size) == rb->wp)
		rb->wp = rb->data;

	pthread_mutex_unlock(&rb->mutex);
}

void ring_buffer_fetch(struct ring_buffer *rb, unsigned char *data, size_t len, size_t *out_len)
{
	intptr_t available;
	size_t real_len;

	if (!rb) {
		*out_len = 0;
		return;
	}

	if (len > rb->size) {
		*out_len = 0;
		return;
	}

	pthread_mutex_lock(&rb->mutex);

	available = rb->wp - rb->rp;

	/* Simple case: Copy difference between read and write ptr. */
	if (available > 0) {
		real_len = available > len ? len : available;
		memcpy(data, rb->rp, real_len);
		*out_len = real_len;
		rb->rp += real_len;
	} else if (available < 0) {
		/* Copy first part */
		available = (rb->data + rb->size) - rb->rp;
		real_len = available > len ? len : available;
		memcpy(data, rb->rp, real_len);

		len -= real_len;
		data += real_len;
		*out_len = real_len;
		rb->rp += real_len;

		if (rb->rp == (rb->data + rb->size))
			rb->rp = rb->data;

		/* Copy second part */
		if (len > 0) {
			available = rb->wp - rb->rp;
			real_len = available > len ? len : available;

			memcpy(data, rb->rp, real_len);

			rb->rp += real_len;
			*out_len += real_len;
		}
	} else {
		*out_len = 0;
	}

	if (rb->rp == (rb->data + rb->size))
		rb->rp = rb->data;

	pthread_mutex_unlock(&rb->mutex);
}
