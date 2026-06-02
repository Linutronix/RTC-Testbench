// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2026 Linutronix GmbH
 */

#include <pthread.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <cmocka.h>

#include "ring_buffer.h"

/*
 * ring_buffer requires init_mutex().
 */
void init_mutex(pthread_mutex_t *mutex)
{
	pthread_mutex_init(mutex, NULL);
}

static void test_fetch_empty(void **state)
{
	struct ring_buffer *rb = ring_buffer_allocate(128);
	unsigned char data[8];
	size_t len;

	(void)state;

	assert_non_null(rb);

	ring_buffer_fetch(rb, data, sizeof(data), &len);

	assert_int_equal(len, 0);

	ring_buffer_free(rb);
}

static void test_basic_usage(void **state)
{
	struct ring_buffer *rb = ring_buffer_allocate(128);
	unsigned char data2[48];
	unsigned char data[16];
	size_t len;

	(void)state;

	assert_non_null(rb);

	for (size_t i = 0; i < sizeof(data); i++)
		data[i] = i;

	ring_buffer_add(rb, data, sizeof(data));
	ring_buffer_add(rb, data, sizeof(data));
	ring_buffer_add(rb, data, sizeof(data));

	ring_buffer_fetch(rb, data2, sizeof(data2), &len);

	assert_int_equal(len, sizeof(data2));

	assert_memory_equal(data, data2, sizeof(data));
	assert_memory_equal(data, data2 + sizeof(data), sizeof(data));
	assert_memory_equal(data, data2 + sizeof(data) + sizeof(data), sizeof(data));

	ring_buffer_free(rb);
}

static void test_drop_oldest(void **state)
{
	struct ring_buffer *rb = ring_buffer_allocate(8);
	unsigned char data3[4] = {'i', 'j', 'k', 'l'};
	unsigned char data2[4] = {'e', 'f', 'g', 'h'};
	unsigned char data1[4] = {'a', 'b', 'c', 'd'};
	unsigned char out[8];
	size_t len;

	(void)state;

	assert_non_null(rb);

	ring_buffer_add(rb, data1, sizeof(data1));
	ring_buffer_add(rb, data2, sizeof(data2));
	ring_buffer_add(rb, data3, sizeof(data3));

	ring_buffer_fetch(rb, out, sizeof(out), &len);

	assert_int_equal(len, sizeof(out));

	assert_memory_equal(out, data2, sizeof(data2));
	assert_memory_equal(out + sizeof(data2), data3, sizeof(data3));

	ring_buffer_free(rb);
}

static void test_full(void **state)
{
	struct ring_buffer *rb = ring_buffer_allocate(8);
	unsigned char data2[4] = {'e', 'f', 'g', 'h'};
	unsigned char data1[4] = {'a', 'b', 'c', 'd'};
	unsigned char out[8];
	size_t len;

	(void)state;

	assert_non_null(rb);

	ring_buffer_add(rb, data1, sizeof(data1));
	ring_buffer_add(rb, data2, sizeof(data2));

	ring_buffer_fetch(rb, out, sizeof(out), &len);

	assert_int_equal(len, sizeof(out));

	assert_memory_equal(out, data1, sizeof(data1));
	assert_memory_equal(out + sizeof(data1), data2, sizeof(data2));

	ring_buffer_free(rb);
}

static void test_wrap_around(void **state)
{
	struct ring_buffer *rb = ring_buffer_allocate(8);
	unsigned char data1[8] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'};
	unsigned char data2[6] = {'i', 'j', 'k', 'l', 'm', 'n'};
	unsigned char out_expected[6] = {'a', 'b', 'c', 'd', 'e', 'f'};
	unsigned char out_expected2[8] = {'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n'};
	unsigned char out[6];
	unsigned char out2[8];
	size_t len;

	(void)state;

	assert_non_null(rb);

	/* Add 8 bytes -> full */
	ring_buffer_add(rb, data1, sizeof(data1));

	/* Drain 6 bytes */
	ring_buffer_fetch(rb, out, sizeof(out), &len);
	assert_int_equal(len, sizeof(out));
	assert_memory_equal(out, out_expected, sizeof(out));

	/* Add 6 bytes again to force wrap around */
	ring_buffer_add(rb, data2, sizeof(data2));

	/* Should be 8 bytes in total */
	ring_buffer_fetch(rb, out2, sizeof(out2), &len);
	assert_int_equal(len, sizeof(out2));

	assert_memory_equal(out2, out_expected2, sizeof(out2));

	ring_buffer_free(rb);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_fetch_empty), cmocka_unit_test(test_basic_usage),
		cmocka_unit_test(test_drop_oldest), cmocka_unit_test(test_full),
		cmocka_unit_test(test_wrap_around),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
