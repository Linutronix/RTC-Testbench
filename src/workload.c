// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025 Intel Corporation
 */
#include <dlfcn.h>

#include "stat.h"
#include "workload.h"

/*
 * Parse input for arguments store them in argc for count and argv for vector
 * of arguments.
 */
static void string_to_argc_argv(const char *input, int *argc, char ***argv)
{
	char *temp_input = strdup(input); /* Duplicate to avoid modifying original */
	int count = 1, i = 1;
	char *token;

	/* First pass: count the number of arguments */
	token = strtok(temp_input, " ");
	while (token) {
		count++;
		token = strtok(NULL, " ");
	}

	/* Allocate memory for argv array */
	*argv = malloc(count * sizeof(char *));
	if (*argv == NULL) {
		fprintf(stderr, "Memory allocation failed\n");
		exit(1);
	}

	/* Second pass: populate argv */
	strcpy(temp_input, input); /* Reset temp_input with original input */
	token = strtok(temp_input, " ");
	while (token) {
		(*argv)[i++] = strdup(token); /* Duplicate token and assign */
		token = strtok(NULL, " ");
	}
	(*argv)[0] = strdup("Workload");

	*argc = count;    /* Set argc to the number of arguments */
	free(temp_input); /* Free the temporary input string */
}

void *workload_thread_routine(void *data)
{
	struct thread_context *thread_context = data;
	struct workload_config *wl_cfg = thread_context->workload;
	struct timespec start_ts, timeout;

	pthread_mutex_lock(&wl_cfg->workload_mutex);
	/* Run until we are ready to stop */
	while (!thread_context->stop) {
		clock_gettime(app_config.application_clock_id, &start_ts);
		timeout = start_ts;
		timeout.tv_sec++;
		/* Check for spurious wakeups */
		if (wl_cfg->workload_run) {
			wl_cfg->workload_function(wl_cfg->workload_argc, wl_cfg->workload_argv);
			wl_cfg->workload_done = 1;
			wl_cfg->workload_run = 0;
			stat_frame_workload(wl_cfg->associated_frame,
					    wl_cfg->workload_sequence_counter, start_ts);
			wl_cfg->workload_sequence_counter++;
		}
		pthread_cond_timedwait(&wl_cfg->workload_cond, &wl_cfg->workload_mutex, &timeout);
	}
	return NULL;
}

void workload_context_init(struct thread_context *thread_context, char *workload_file,
			   char *workload_function, char *workload_arguments,
			   char *workload_setup_function, char *workload_setup_arguments,
			   enum stat_frame_type frame_type)
{
	struct workload_config *wl_cfg = thread_context->workload;
	char *error;

	wl_cfg->workload_handler = dlopen(workload_file, RTLD_NOW | RTLD_GLOBAL);

	if (!wl_cfg->workload_handler) {
		error = dlerror();
		fprintf(stderr, "Error: Unable to open workload: %s. %s\n", workload_file, error);
		exit(EXIT_FAILURE);
	}

	if (workload_setup_function) {
		wl_cfg->workload_setup_function =
			dlsym(wl_cfg->workload_handler, workload_setup_function);
		if (!wl_cfg->workload_setup_function) {
			fprintf(stderr, "Error: Unable to find setup function: %s\n",
				workload_setup_function);
			exit(EXIT_FAILURE);
		}
	}

	wl_cfg->workload_function = dlsym(wl_cfg->workload_handler, workload_function);
	if (!wl_cfg->workload_function) {
		fprintf(stderr, "Error: Unable to find function: %s\n", workload_function);
		exit(EXIT_FAILURE);
	}

	if (workload_arguments) {
		string_to_argc_argv(workload_arguments, &wl_cfg->workload_argc,
				    &wl_cfg->workload_argv);
	} else {
		wl_cfg->workload_argc = 0;
		wl_cfg->workload_argv = NULL;
	}

	if (workload_setup_arguments) {
		string_to_argc_argv(workload_setup_arguments, &wl_cfg->workload_setup_argc,
				    &wl_cfg->workload_setup_argv);
	} else {
		wl_cfg->workload_setup_argc = 0;
		wl_cfg->workload_setup_argv = NULL;
	}

	pthread_mutex_init(&wl_cfg->workload_mutex, NULL);
	pthread_cond_init(&wl_cfg->workload_cond, NULL);

	wl_cfg->associated_frame = frame_type;

	/* Call the setup function if it exists */
	if (wl_cfg->workload_setup_function)
		wl_cfg->workload_setup_function(wl_cfg->workload_setup_argc,
						wl_cfg->workload_setup_argv);
}

void workload_thread_free(struct thread_context *thread_context)
{
	if (!thread_context)
		return;
	dlclose(thread_context->workload->workload_handler);
	free(thread_context->workload);
}
