// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025 Intel Corporation
 * Copyright (c) 2026 Linutronix GmbH
 */
#ifndef _WORKLOAD_H_
#define _WORKLOAD_H_

#include "config.h"
#include "stat.h"
#include "thread.h"

struct thread_context;

struct workload_instance {
	int id;     /* Which workload instance is it? */
	int cpu;    /* On which CPU does this instance run on? */
	void *priv; /* Pointer to private data. */
};

struct workload_config {
	pthread_t workload_task_id;
	uint64_t workload_sequence_counter;
	pthread_mutex_t workload_mutex;
	pthread_cond_t workload_cond;
	void *workload_handler;
	int (*workload_function)(struct workload_instance *instance, int argc, char **argv);
	int workload_argc;
	char **workload_argv;
	int (*workload_setup_function)(struct workload_instance *instance, int argc, char **argv);
	int workload_setup_argc;
	char **workload_setup_argv;
	void (*workload_teardown_function)(struct workload_instance *instance);
	int workload_running;
	enum stat_frame_type associated_frame;
	struct workload_instance instances[WORKLOAD_MAX];
};

int workload_context_init(struct thread_context *thread_context);
void workload_thread_free(struct thread_context *thread_context);
void workload_thread_wait_for_finish(struct thread_context *thread_context);

void workload_check_finished(struct thread_context *thread_context);
void workload_signal(struct thread_context *thread_context, unsigned int received);

#endif /* _WORKLOAD_H_ */
