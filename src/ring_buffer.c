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
	rb->count = 0;
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
		rb->wp = rb->data;
		memcpy(rb->wp, data + available, len - available);
		rb->wp += len - available;
	}

	if ((rb->data + rb->size) == rb->wp)
		rb->wp = rb->data;

	/* Advance read pointer in case of overflow. Oldest data get's dropped first. */
	if (rb->count + len > rb->size) {
		rb->rp = rb->wp;
		rb->count = rb->size;
	} else {
		rb->count += len;
	}

	pthread_mutex_unlock(&rb->mutex);
}

void ring_buffer_fetch(struct ring_buffer *rb, unsigned char *data, size_t len, size_t *out_len)
{
	size_t available, real_len;

	if (!rb) {
		*out_len = 0;
		return;
	}

	if (len > rb->size) {
		*out_len = 0;
		return;
	}

	pthread_mutex_lock(&rb->mutex);

	if (rb->count == 0) {
		*out_len = 0;
		pthread_mutex_unlock(&rb->mutex);
		return;
	}

	real_len = len < rb->count ? len : rb->count;
	available = (rb->data + rb->size) - rb->rp;

	if (real_len <= available) {
		/* Simple case: Copy in direction towards end */
		memcpy(data, rb->rp, real_len);
		rb->rp += real_len;
	} else {
		/* Wrap case: Copy first and second part */
		memcpy(data, rb->rp, available);
		memcpy(data + available, rb->data, real_len - available);

		rb->rp = rb->data + (real_len - available);
	}

	if (rb->rp == (rb->data + rb->size))
		rb->rp = rb->data;

	rb->count -= real_len;
	*out_len = real_len;

	pthread_mutex_unlock(&rb->mutex);
}
