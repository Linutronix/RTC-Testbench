// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2025 Intel Corporation
 * Copyright (c) 2025-2026 Linutronix GmbH
 */
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>

#include "config.h"
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
	struct workload_thread_context *ctx;
	struct thread_context *thread_context;
	struct workload_config *wl_cfg;
	struct workload_thread *thread;

	ctx = data;
	thread_context = ctx->thread_context;
	wl_cfg = thread_context->workload;
	thread = &wl_cfg->threads[ctx->id];

	/* Run until we are ready to stop. */
	while (!thread_context->stop) {
		struct timespec start_ts, timeout;
		int ret;

		clock_gettime(CLOCK_MONOTONIC, &timeout);
		timeout.tv_sec++;

		/* Wait for workload to be run. Signaled by Rx threads. */
		pthread_mutex_lock(&thread->workload_mutex);
		ret = pthread_cond_timedwait(&thread->workload_cond, &thread->workload_mutex,
					     &timeout);
		pthread_mutex_unlock(&thread->workload_mutex);

		/* In case of timeout, check !stop again. */
		if (ret == ETIMEDOUT)
			continue;

		clock_gettime(app_config.application_clock_id, &start_ts);
		ret = wl_cfg->workload_function(&thread->instance, wl_cfg->workload_argc,
						wl_cfg->workload_argv);
		if (ret)
			log_message(LOG_LEVEL_WARNING,
				    "Workload: Workload function returned error %d\n", ret);

		/* workload_running is checked by Tx threads to indicate workload time overruns. */
		pthread_mutex_lock(&thread->workload_mutex);
		thread->workload_running = 0;
		pthread_mutex_unlock(&thread->workload_mutex);

		stat_frame_workload(ctx->id, wl_cfg->associated_frame,
				    thread->workload_sequence_counter, start_ts);
		thread->workload_sequence_counter++;
	}

	return NULL;
}

int workload_context_init(struct thread_context *thread_context)
{
	struct traffic_class_config *conf = thread_context->conf;
	struct workload_config *wl_cfg;
	char *error;
	int ret, i;

	if (!conf->rx_workload_enabled)
		return 0;

	thread_context->workload = calloc(1, sizeof(struct workload_config));
	if (!thread_context->workload) {
		fprintf(stderr, "Failed to allocate workload!\n");
		return -ENOMEM;
	}
	wl_cfg = thread_context->workload;

	wl_cfg->workload_handler = dlopen(conf->workload_file, RTLD_NOW | RTLD_GLOBAL);
	if (!wl_cfg->workload_handler) {
		error = dlerror();
		fprintf(stderr, "Error: Unable to open workload '%s': %s\n", conf->workload_file,
			error);
		ret = -EINVAL;
		goto dlopen;
	}

	if (conf->workload_setup_function) {
		wl_cfg->workload_setup_function =
			dlsym(wl_cfg->workload_handler, conf->workload_setup_function);
		if (!wl_cfg->workload_setup_function) {
			fprintf(stderr, "Error: Unable to find setup function: %s\n",
				conf->workload_setup_function);
			ret = -EINVAL;
			goto dl;
		}
	}

	if (conf->workload_teardown_function) {
		wl_cfg->workload_teardown_function =
			dlsym(wl_cfg->workload_handler, conf->workload_teardown_function);
		if (!wl_cfg->workload_teardown_function) {
			fprintf(stderr, "Error: Unable to find teardown function: %s\n",
				conf->workload_teardown_function);
			ret = -EINVAL;
			goto dl;
		}
	}

	wl_cfg->workload_function = dlsym(wl_cfg->workload_handler, conf->workload_function);
	if (!wl_cfg->workload_function) {
		fprintf(stderr, "Error: Unable to find function: %s\n", conf->workload_function);
		ret = -EINVAL;
		goto dl;
	}

	wl_cfg->workload_argc = 0;
	wl_cfg->workload_argv = NULL;
	if (conf->workload_arguments) {
		ret = string_to_argc_argv(conf->workload_arguments, &wl_cfg->workload_argc,
					  &wl_cfg->workload_argv);
		if (ret)
			goto dl;
	}

	wl_cfg->workload_setup_argc = 0;
	wl_cfg->workload_setup_argv = NULL;
	if (conf->workload_setup_arguments) {
		ret = string_to_argc_argv(conf->workload_setup_arguments,
					  &wl_cfg->workload_setup_argc,
					  &wl_cfg->workload_setup_argv);
		if (ret)
			goto argv;
	}

	wl_cfg->associated_frame = thread_context->frame_type;

	for (i = 0; i < conf->workload_thread_cpus_num; i++) {
		struct workload_thread *thread = &wl_cfg->threads[i];
		struct workload_instance *instance = &thread->instance;
		struct workload_thread_context *ctx = &wl_cfg->ctx[i];

		/* Initialize workload instances */
		instance->id = i;
		instance->cpu = conf->workload_thread_cpus[i];
		instance->priv = NULL;

		init_mutex(&thread->workload_mutex);
		init_condition_variable(&thread->workload_cond);

		ctx->thread_context = thread_context;
		ctx->id = i;

		/* Call the setup function if it exists */
		if (wl_cfg->workload_setup_function) {
			ret = wl_cfg->workload_setup_function(instance, wl_cfg->workload_setup_argc,
							      wl_cfg->workload_setup_argv);
			if (ret) {
				fprintf(stderr,
					"Workload setup function '%s' return with failure code: "
					"%d\n",
					conf->workload_setup_function, ret);
				goto setup;
			}
		}
	}

	/* Create and start threads */
	for (i = 0; i < conf->workload_thread_cpus_num; i++) {
		struct workload_thread *thread = &wl_cfg->threads[i];
		struct workload_thread_context *ctx = &wl_cfg->ctx[i];

		ret = create_rt_thread(&thread->workload_task_id, conf->workload_thread_priority,
				       conf->workload_thread_cpus[i], &workload_thread_routine, ctx,
				       "WorkloadTask%d", i);
		if (ret) {
			fprintf(stderr, "Failed to create Workload Thread for CPU %d!\n",
				conf->workload_thread_cpus[i]);
			goto thread;
		}
	}

	return 0;

thread:
	thread_context->stop = 1;
	for (int j = i - 1; j >= 0; --j)
		pthread_join(wl_cfg->threads[j].workload_task_id, NULL);
setup:
	if (wl_cfg->workload_teardown_function)
		for (int j = i - 1; j >= 0; --j)
			wl_cfg->workload_teardown_function(&wl_cfg->threads[j].instance);
	free_argv(wl_cfg->workload_setup_argc, wl_cfg->workload_setup_argv);
argv:
	free_argv(wl_cfg->workload_argc, wl_cfg->workload_argv);
dl:
	dlclose(thread_context->workload->workload_handler);
dlopen:
	free(thread_context->workload);
	return ret;
}

void workload_thread_free(struct thread_context *thread_context)
{
	struct traffic_class_config *conf;
	struct workload_config *wl_cfg;

	if (!thread_context)
		return;

	conf = thread_context->conf;

	if (!conf || !conf->rx_workload_enabled)
		return;

	wl_cfg = thread_context->workload;

	if (wl_cfg->workload_teardown_function)
		for (int i = 0; i < conf->workload_thread_cpus_num; i++)
			wl_cfg->workload_teardown_function(&wl_cfg->threads[i].instance);

	free_argv(wl_cfg->workload_argc, wl_cfg->workload_argv);
	free_argv(wl_cfg->workload_setup_argc, wl_cfg->workload_setup_argv);

	dlclose(wl_cfg->workload_handler);

	free(thread_context->workload);
}

void workload_thread_wait_for_finish(struct thread_context *thread_context)
{
	struct traffic_class_config *conf;
	struct workload_config *wl_cfg;

	if (!thread_context)
		return;

	conf = thread_context->conf;

	if (!conf || !conf->rx_workload_enabled)
		return;

	wl_cfg = thread_context->workload;

	for (int i = 0; i < conf->workload_thread_cpus_num; i++)
		pthread_join(wl_cfg->threads[i].workload_task_id, NULL);
}

void workload_check_finished(struct thread_context *thread_context)
{
	const struct traffic_class_config *conf = thread_context->conf;
	struct workload_config *wl_cfg = thread_context->workload;

	if (!conf->rx_workload_enabled)
		return;

	/* Increment workload outlier count if workload did not finish. */
	for (int i = 0; i < conf->workload_thread_cpus_num; i++) {
		struct workload_thread *thread = &wl_cfg->threads[i];

		pthread_mutex_lock(&thread->workload_mutex);
		if (thread->workload_running) {
			stat_inc_workload_outlier(i, thread_context->frame_type);
			log_message(LOG_LEVEL_DEBUG, "Workload for CPU %d did not finish!\n",
				    conf->workload_thread_cpus[i]);
		}
		pthread_mutex_unlock(&thread->workload_mutex);
	}
}

void workload_signal(struct thread_context *thread_context, unsigned int received)
{
	const struct traffic_class_config *conf = thread_context->conf;
	struct workload_config *wl_cfg = thread_context->workload;

	if (!conf->rx_workload_enabled)
		return;

	/* Run workload if we received frames or prewarm is enabled */
	if (received || conf->rx_workload_prewarm) {
		for (int i = 0; i < conf->workload_thread_cpus_num; i++) {
			struct workload_thread *thread = &wl_cfg->threads[i];

			pthread_mutex_lock(&thread->workload_mutex);
			thread->workload_running = 1;
			pthread_cond_signal(&thread->workload_cond);
			pthread_mutex_unlock(&thread->workload_mutex);
		}
	}
}
