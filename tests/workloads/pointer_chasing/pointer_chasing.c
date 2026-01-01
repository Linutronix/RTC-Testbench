// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025 Intel Corporation
 */
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "log.h"
#include "pointer_chasing.h"

ptr_chaser_t *ptr_chaser;

int ptr_chase_setup(int argc, char *argv[])
{
	uint64_t buff, span;
	int ret = 0;

	if (argc != 3) {
		log_message(LOG_LEVEL_INFO, "[pointer_chasing]: Usage: <buff_size> <span_size>\n");
		log_message(LOG_LEVEL_INFO, "[pointer_chasing]: Example: 0x4A0000 0x129000\n");
		return -EINVAL;
	}

	buff = strtoull(argv[1], NULL, 16);
	span = strtoull(argv[2], NULL, 16);

	log_message(LOG_LEVEL_INFO, "[pointer_chasing]: buff: 0x%" PRIx64 ", span: 0x%" PRIx64 "\n",
		    buff, span);

	if (buff == 0 || span == 0 || (span > buff)) {
		log_message(LOG_LEVEL_INFO, "[pointer_chasing]: Invalid buffer/span sizes.\n");
		return -EINVAL;
	}

	ptr_chaser = (ptr_chaser_t *)calloc(1, sizeof(ptr_chaser_t));
	if (!ptr_chaser) {
		log_message(LOG_LEVEL_INFO, "[pointer_chasing]: Memory allocation failed.\n");
		return -ENOMEM;
	}

	ptr_chaser->buff = buff;
	ptr_chaser->span = span;
	ret = generate_linked_list(ptr_chaser, 0xdeadbeef);
	if (ret)
		return ret;

	ptr_chaser->workload = (void *)__chasing_code_loop;

	return 0;
}

int run_ptr_chasing(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	__ptr_chasing_run_workload(ptr_chaser);

	return 0;
}

int generate_linked_list(ptr_chaser_t *ptr_chaser, unsigned int seed)
{
	ptr_node *head;

	srand(seed);
	head = create_linked_list();
	if (!head) {
		log_message(LOG_LEVEL_INFO, "[pointer_chasing]: Creating Linked List failed.\n");
		return -ENOMEM;
	}

	ptr_chaser->head = (void *)head;
	return 0;
}

/* Get random int in a range of [0, max) */
int random_int(int max)
{
	return rand() % max;
}

ptr_node *create_linked_list(void)
{
	ptr_node *ptr, *head;
	uint64_t i, nr_nodes;
	int offset;

	nr_nodes = ptr_chaser->span / sizeof(ptr_node);

	/* Allocate large buffer that we will read randomly from */
	ptr_node *mem = (ptr_node *)malloc(ptr_chaser->buff * sizeof(ptr_node));
	if (!mem) {
		log_message(LOG_LEVEL_INFO,
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

__attribute__((destructor)) int ptr_chaser_finish(void)
{
	free(ptr_chaser);
	return 0;
}
