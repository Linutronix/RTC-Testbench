// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025 Intel Corporation
 * Copyright (c) 2025-2026 Linutronix GmbH
 */
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>

#include "log.h"
#include "stat.h"
#include "thread.h"
#include "workload.h"

/*
 * Parse input for arguments store them in argc for count and argv for vector
 * of arguments.
 */
static int string_to_argc_argv(const char *input, int *argc, char ***argv)
{
	char *temp_input = strdup(input); /* Duplicate to avoid modifying original */
	int count = 1, i = 1, ret;
	char *token;

	if (!temp_input)
		return -ENOMEM;

	/* First pass: count the number of arguments */
	token = strtok(temp_input, " ");
	while (token) {
		count++;
		token = strtok(NULL, " ");
	}

	/* Allocate memory for argv array */
	*argv = malloc(count * sizeof(char *));
	if (*argv == NULL) {
		ret = -ENOMEM;
		goto err_argv;
	}

	/* Second pass: populate argv */
	strcpy(temp_input, input); /* Reset temp_input with original input */
	token = strtok(temp_input, " ");
	while (token) {
		(*argv)[i++] = strdup(token); /* Duplicate token and assign */
		token = strtok(NULL, " ");
	}
	(*argv)[0] = strdup("Workload");
	if ((*argv)[0] == NULL) {
		ret = -ENOMEM;
		goto err_workload;
	}

	*argc = count; /* Set argc to the number of arguments */

	free(temp_input);
	return 0;

err_workload:
	free(*argv);
err_argv:
	free(temp_input); /* Free the temporary input string */
	return ret;
}

/* Free argv array allocated by string_to_argc_argv() with strdup(). */
static void free_argv(int argc, char **argv)
{
	for (int i = 0; i < argc; i++)
		free(argv[i]);
	free(argv);
}

void *workload_thread_routine(void *data)
{
	struct thread_context *thread_context = data;
	struct workload_config *wl_cfg = thread_context->workload;

	/* Run until we are ready to stop. */
	while (!thread_context->stop) {
		struct timespec start_ts, timeout;
		int ret;

		clock_gettime(CLOCK_MONOTONIC, &timeout);
		timeout.tv_sec++;

		/* Wait for workload to be run. Signaled by Rx threads. */
		pthread_mutex_lock(&wl_cfg->workload_mutex);
		ret = pthread_cond_timedwait(&wl_cfg->workload_cond, &wl_cfg->workload_mutex,
					     &timeout);
		pthread_mutex_unlock(&wl_cfg->workload_mutex);

		/* In case of timeout, check !stop again. */
		if (ret == ETIMEDOUT)
			continue;

		clock_gettime(app_config.application_clock_id, &start_ts);
		ret = wl_cfg->workload_function(wl_cfg->workload_argc, wl_cfg->workload_argv);
		if (ret)
			log_message(LOG_LEVEL_WARNING,
				    "Workload: Workload function returned error %d\n", ret);

		/* workload_running is checked by Tx threads to indicate workload time overruns. */
		pthread_mutex_lock(&wl_cfg->workload_mutex);
		wl_cfg->workload_running = 0;
		pthread_mutex_unlock(&wl_cfg->workload_mutex);

		stat_frame_workload(wl_cfg->associated_frame, wl_cfg->workload_sequence_counter,
				    start_ts);
		wl_cfg->workload_sequence_counter++;
	}

	return NULL;
}

int workload_context_init(struct thread_context *thread_context, const char *workload_file,
			  const char *workload_function, const char *workload_arguments,
			  const char *workload_setup_function, const char *workload_setup_arguments,
			  enum stat_frame_type frame_type)
{
	struct workload_config *wl_cfg = thread_context->workload;
	char *error;
	int ret;

	wl_cfg->workload_handler = dlopen(workload_file, RTLD_NOW | RTLD_GLOBAL);
	if (!wl_cfg->workload_handler) {
		error = dlerror();
		fprintf(stderr, "Error: Unable to open workload '%s': %s\n", workload_file, error);
		return -EINVAL;
	}

	if (workload_setup_function) {
		wl_cfg->workload_setup_function =
			dlsym(wl_cfg->workload_handler, workload_setup_function);
		if (!wl_cfg->workload_setup_function) {
			fprintf(stderr, "Error: Unable to find setup function: %s\n",
				workload_setup_function);
			ret = -EINVAL;
			goto dl;
		}
	}

	wl_cfg->workload_function = dlsym(wl_cfg->workload_handler, workload_function);
	if (!wl_cfg->workload_function) {
		fprintf(stderr, "Error: Unable to find function: %s\n", workload_function);
		ret = -EINVAL;
		goto dl;
	}

	wl_cfg->workload_argc = 0;
	wl_cfg->workload_argv = NULL;
	if (workload_arguments) {
		ret = string_to_argc_argv(workload_arguments, &wl_cfg->workload_argc,
					  &wl_cfg->workload_argv);
		if (ret)
			goto dl;
	}

	wl_cfg->workload_setup_argc = 0;
	wl_cfg->workload_setup_argv = NULL;
	if (workload_setup_arguments) {
		ret = string_to_argc_argv(workload_setup_arguments, &wl_cfg->workload_setup_argc,
					  &wl_cfg->workload_setup_argv);
		if (ret)
			goto argv;
	}

	init_mutex(&wl_cfg->workload_mutex);
	init_condition_variable(&wl_cfg->workload_cond);

	wl_cfg->associated_frame = frame_type;

	/* Call the setup function if it exists */
	if (wl_cfg->workload_setup_function) {
		ret = wl_cfg->workload_setup_function(wl_cfg->workload_setup_argc,
						      wl_cfg->workload_setup_argv);
		if (ret) {
			fprintf(stderr,
				"Workload setup function '%s' return with failure code: %d\n",
				workload_setup_function, ret);
			goto setup;
		}
	}

	return 0;

setup:
	free_argv(wl_cfg->workload_setup_argc, wl_cfg->workload_setup_argv);
argv:
	free_argv(wl_cfg->workload_argc, wl_cfg->workload_argv);
dl:
	dlclose(thread_context->workload->workload_handler);
	return ret;
}

void workload_thread_free(struct thread_context *thread_context)
{
	struct workload_config *wl_cfg;

	if (!thread_context)
		return;

	wl_cfg = thread_context->workload;

	free_argv(wl_cfg->workload_argc, wl_cfg->workload_argv);
	free_argv(wl_cfg->workload_setup_argc, wl_cfg->workload_setup_argv);

	dlclose(wl_cfg->workload_handler);

	free(thread_context->workload);
}

void workload_check_finished(struct thread_context *thread_context)
{
	const struct traffic_class_config *conf = thread_context->conf;
	struct workload_config *wl_cfg = thread_context->workload;

	if (!conf->rx_workload_enabled)
		return;

	/* Increment workload outlier count if workload did not finish. */
	pthread_mutex_lock(&wl_cfg->workload_mutex);
	if (wl_cfg->workload_running) {
		stat_inc_workload_outlier(thread_context->frame_type);
		log_message(LOG_LEVEL_DEBUG, "Workload did not finish!\n");
	}
	pthread_mutex_unlock(&wl_cfg->workload_mutex);
}

void workload_signal(struct thread_context *thread_context, unsigned int received)
{
	const struct traffic_class_config *conf = thread_context->conf;
	struct workload_config *wl_cfg = thread_context->workload;

	if (!conf->rx_workload_enabled || !conf->rx_mirror_enabled)
		return;

	/* Run workload if we received frames or prewarm is enabled */
	if (received || conf->rx_workload_prewarm) {
		pthread_mutex_lock(&wl_cfg->workload_mutex);
		wl_cfg->workload_running = 1;
		pthread_cond_signal(&wl_cfg->workload_cond);
		pthread_mutex_unlock(&wl_cfg->workload_mutex);
	}
}
