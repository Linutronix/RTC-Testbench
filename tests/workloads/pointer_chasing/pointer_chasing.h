// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025 Intel Corporation
 */

#ifndef _POINTER_CHASING_H_
#define _POINTER_CHASING_H_

#include <stdint.h>

#define CACHE_LINE_SIZE 64

typedef union ptr_node {
	struct {
		union ptr_node *next;
		int val;
	};
	uint8_t bytes[64];
} ptr_node;

typedef struct ptr_chaser {
	uint64_t buff;
	uint64_t span;
	void *head;
	void (*workload)(struct ptr_chaser *);
} ptr_chaser_t;

extern void __chasing_code_loop(void);
__asm__(".global __chasing_code_loop        ;\n\t"
	"__chasing_code_loop:               ;\n\t"
	"mov (%rax), %rax              ;\n\t"
	"test %rax, %rax               ;\n\t"
	"jne __chasing_code_loop          ;\n\t"
	"ret                           ;\n\t");

/*
 * Inline function used to run workload.
 * code_ptr: holds a pointer to workload bytecode
 * %%RAX: holds a pointer to head of data set
 */
static __attribute__((always_inline)) inline void __ptr_chasing_run_workload(
	ptr_chaser_t *ptr_chaser)
{
	__asm__ __volatile__("call *%[code_ptr]   ;\n\t"
			     :
			     : [code_ptr] "g"(ptr_chaser->workload), "a"(ptr_chaser->head)
			     :);
}

int generate_linked_list(ptr_chaser_t *ptr_chaser, unsigned int seed);
union ptr_node *create_linked_list(void);
int ptr_chase_setup(int argc, char *argv[]);
void run_ptr_chasing(void);

#endif /* _POINTER_CHASING_H_ */
