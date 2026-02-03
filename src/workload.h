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

/* Instance per workload thread passed to ptr_chasing/jacobi/... */
struct workload_instance {
	int id;     /* Which workload instance is it? */
	int cpu;    /* On which CPU does this instance run on? */
	void *priv; /* Pointer to private data. */
};

/* Thread context for workload_thread_routine() */
struct workload_thread_context {
	struct thread_context *thread_context;
	int id;
};

/* Data per workload thread. */
struct workload_thread {
	struct workload_instance instance;
	pthread_t workload_task_id;
	uint64_t workload_sequence_counter;
	pthread_mutex_t workload_mutex;
	pthread_cond_t workload_cond;
	int workload_running;
};

/* Single workload config per traffic class. */
struct workload_config {
	/* Specific per workload thread data */
	struct workload_thread threads[WORKLOAD_MAX];

	/* Structs passed to workload_thread_routine() */
	struct workload_thread_context ctx[WORKLOAD_MAX];

	/* Common for all workload threads */
	void *workload_handler;
	int (*workload_function)(struct workload_instance *instance, int argc, char **argv);
	int workload_argc;
	char **workload_argv;
	int (*workload_setup_function)(struct workload_instance *instance, int argc, char **argv);
	int workload_setup_argc;
	char **workload_setup_argv;
	void (*workload_teardown_function)(struct workload_instance *instance);
	enum stat_frame_type associated_frame;
};

int workload_context_init(struct thread_context *thread_context);
void workload_thread_free(struct thread_context *thread_context);
void workload_thread_wait_for_finish(struct thread_context *thread_context);

void workload_check_finished(struct thread_context *thread_context);
void workload_signal(struct thread_context *thread_context, unsigned int received);

#endif /* _WORKLOAD_H_ */
