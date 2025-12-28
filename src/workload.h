// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025 Intel Corporation
 */
#ifndef _WORKLOAD_H_
#define _WORKLOAD_H_

#include "config.h"
#include "stat.h"
#include "thread.h"

struct thread_context; // Forward Declaration

struct workload_config {
	pthread_t workload_task_id;
	uint64_t workload_sequence_counter;
	pthread_mutex_t workload_mutex;
	pthread_cond_t workload_cond;
	void *workload_handler;
	int (*workload_function)(int argc, char **argv);
	int workload_argc;
	char **workload_argv;
	int (*workload_setup_function)(int argc, char **argv);
	int workload_setup_argc;
	char **workload_setup_argv;
	volatile int workload_run;
	volatile int workload_done;
	enum stat_frame_type associated_frame;
};

void *workload_thread_routine(void *data);
int workload_context_init(struct thread_context *thread_context, const char *workload_file,
			  const char *workload_function, const char *workload_argument,
			  const char *workload_setup_function, const char *workload_setup_argument,
			  enum stat_frame_type frame_type);
void workload_thread_free(struct thread_context *thread_context);

#endif /* _WORKLOAD_H_ */
