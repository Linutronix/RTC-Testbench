// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025 Intel Corporation
 * Copyright (c) 2026 Linutronix GmbH
 */
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "pointer_chasing.h"

ptr_chaser_t *ptr_chaser;
ptr_node *mem;

/* Get random int in a range of [0, max) */
static int random_int(int max)
{
	return rand() % max;
}

static ptr_node *create_linked_list(void)
{
	ptr_node *ptr, *head;
	uint64_t i, nr_nodes;
	int offset;

	nr_nodes = ptr_chaser->span / sizeof(ptr_node);

	/* Allocate large buffer that we will read randomly from */
	mem = (ptr_node *)malloc(ptr_chaser->buff * sizeof(ptr_node));
	if (!mem) {
		fprintf(stderr,
			"[pointer_chasing]: Memory allocation failed. Consider reducing size "
			"of the buffer?\n");
		return NULL;
	}

	head = &mem[random_int(ptr_chaser->buff)];
	head->val = 1;
	ptr = head;

	/* Create linked list that will fill a buffer */
	i = 1;
	while (i < nr_nodes) {
		/* Pick a random address in the span */
		offset = random_int(nr_nodes);
		if (mem[offset].val == 0) {
			ptr->next = &mem[offset];
			ptr = ptr->next;
			ptr->val = 1;
			i++;
		}
	}

	return head;
}

static int generate_linked_list(ptr_chaser_t *ptr_chaser, unsigned int seed)
{
	ptr_node *head;

	srand(seed);
	head = create_linked_list();
	if (!head) {
		fprintf(stderr, "[pointer_chasing]: Creating Linked List failed.\n");
		return -ENOMEM;
	}

	ptr_chaser->head = (void *)head;
	return 0;
}

int ptr_chase_setup(int argc, char *argv[])
{
	uint64_t buff, span;
	char *endptr;
	int ret = 0;

	if (argc != 3) {
		fprintf(stderr, "[pointer_chasing]: Usage: <buff_size> <span_size>\n");
		fprintf(stderr, "[pointer_chasing]: Example: 0x4A0000 0x129000\n");
		return -EINVAL;
	}

	errno = 0;
	buff = strtoull(argv[1], &endptr, 16);
	if (errno != 0 || endptr == argv[1] || *endptr != '\0') {
		fprintf(stderr, "[pointer_chasing]: Invalid buffer size.\n");
		return -ERANGE;
	}

	span = strtoull(argv[2], &endptr, 16);
	if (errno != 0 || endptr == argv[2] || *endptr != '\0') {
		fprintf(stderr, "[pointer_chasing]: Invalid span size.\n");
		return -ERANGE;
	}

	fprintf(stderr, "[pointer_chasing]: buff: 0x%" PRIx64 ", span: 0x%" PRIx64 "\n", buff,
		span);

	if (buff == 0 || span == 0 || (span > buff)) {
		fprintf(stderr, "[pointer_chasing]: Invalid buffer/span sizes.\n");
		return -EINVAL;
	}

	ptr_chaser = (ptr_chaser_t *)calloc(1, sizeof(ptr_chaser_t));
	if (!ptr_chaser) {
		fprintf(stderr, "[pointer_chasing]: Memory allocation failed.\n");
		return -ENOMEM;
	}

	ptr_chaser->buff = buff;
	ptr_chaser->span = span;
	ret = generate_linked_list(ptr_chaser, 0xdeadbeef);
	if (ret) {
		free(ptr_chaser);
		ptr_chaser = NULL;
		return ret;
	}

#ifdef __x86_64__
	ptr_chaser->workload = (void *)__chasing_code_loop;
#endif

	return 0;
}

/*
 * Generic ptr_chasing workload function in plain C:
 *
 * Compiles to the following code on x86_64 with gcc 14.2.0:
 *   ptr_loop:
 *     movq       (%rax), %rax ; CODE XREF=run_ptr_chasing+38
 *     testq      %rax, %rax
 *     jne        ptr_loop
 *
 * ARM64 looks similar:
 *   ptr_loop:
 *     ldr        x0, [x0]     ; CODE XREF=run_ptr_chasing+24
 *     cbnz       x0, ptr_loop
 */
static void __attribute__((unused)) * __ptr_chasing_run_workload(ptr_chaser_t *ptr_chaser)
{
	ptr_node *p = ptr_chaser->head;

	while (p)
		p = p->next;

	return p;
}

int run_ptr_chasing(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

#ifdef __x86_64__
	/* Hand written version for x86_64 */
	__ptr_chasing_run_workload_x86_64(ptr_chaser);
#else
	/* For all other architectures */
	__ptr_chasing_run_workload(ptr_chaser);
#endif

	return 0;
}

__attribute__((destructor)) int ptr_chaser_finish(void)
{
	free(mem);
	free(ptr_chaser);
	return 0;
}
