// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2025 Linutronix GmbH
 */

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "app_config.h"

#include "config.h"
#include "log.h"
#include "log_json.h"
#include "net.h"
#include "stat.h"
#include "thread.h"
#include "utils.h"

static void log_json_add_traffic_class(struct log_json_thread_context *ctx,
				       const struct statistics *stat, const char *tc)
{
	char stat_message[4096] = {};
	int ret;

	/* Convert stats to json */
	stat_to_json(stat_message, sizeof(stat_message), stat, tc,
		     app_config.log_json_measurement_name);

	/* Send it via UDP */
	switch (ctx->dest.ss_family) {
	case AF_INET:
		ret = sendto(ctx->socket, stat_message, strlen(stat_message), 0,
			     (struct sockaddr_in *)&ctx->dest, sizeof(struct sockaddr_in));
		break;
	case AF_INET6:
		ret = sendto(ctx->socket, stat_message, strlen(stat_message), 0,
			     (struct sockaddr_in6 *)&ctx->dest, sizeof(struct sockaddr_in6));
		break;
	default:
		ret = -EINVAL;
	}

	if (ret < 0)
		log_message(LOG_LEVEL_DEBUG, "JsonTx: sendto() for statistic message failed: %s\n",
			    strerror(errno));
}

void *log_json_publisher(void *data)
{
	struct log_json_thread_context *ctx = data;
	uint64_t period = app_config.stats_collection_interval_ns;
	struct statistics stats[NUM_FRAME_TYPES];
	struct timespec time;
	int ret;

	/*
	 * Send the statistics periodically to the JSON/UDP host. This thread can run with low
	 * priority to not influence to Application Tasks that much.
	 */
	ret = clock_gettime(app_config.application_clock_id, &time);
	if (ret) {
		fprintf(stderr, "JSON: clock_gettime() failed: %s!", strerror(errno));
		goto out;
	}

	while (!ctx->stop) {
		increment_period(&time, period);
		ret = clock_nanosleep(app_config.application_clock_id, TIMER_ABSTIME, &time, NULL);
		if (ret) {
			pthread_error(ret, "JSON: clock_nanosleep() failed");
			goto out;
		}

		/* Get latest statistics data */
		stat_get_global_stats(stats, sizeof(stats));

		/* Publish via UDP */
		for (int i = 0; i < NUM_FRAME_TYPES; i++) {
			if (config_is_traffic_class_active(stat_frame_type_to_string(i)))
				log_json_add_traffic_class(ctx, &stats[i],
							   stat_frame_type_to_string(i));
		}
	}

out:
	return NULL;
}

struct log_json_thread_context *log_json_thread_create(void)
{
	struct log_json_thread_context *ctx;
	int ret = 0;

	if (!app_config.log_json)
		return NULL;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	/* Allocate UDP client socket */
	ctx->socket = create_udp_cl_socket(app_config.log_json_host, app_config.log_json_port,
					   &ctx->dest);
	if (ctx->socket <= 0) {
		fprintf(stderr, "JSON: Failed to allocate UDP socket for JSON logging!\n");
		goto err_socket;
	}

	/* Start dedicated JSON/UDP pubslishing thread */
	ret = create_rt_thread(&ctx->pid, "LoggerJson", app_config.log_json_thread_priority,
			       app_config.log_json_thread_cpu, log_json_publisher, ctx);

	if (ret) {
		fprintf(stderr, "JSON: Failed to start JSON Logger thread!\n");
		goto err_thread;
	}

	return ctx;

err_thread:
	close(ctx->socket);
err_socket:
	free(ctx);
	return NULL;
}

void log_json_thread_stop(struct log_json_thread_context *ctx)
{
	if (!ctx)
		return;

	ctx->stop = 1;
	pthread_join(ctx->pid, NULL);
}

void log_json_thread_free(struct log_json_thread_context *ctx)
{
	if (!ctx)
		return;

	close(ctx->socket);
	free(ctx);
}

void log_json_thread_wait_for_finish(struct log_json_thread_context *ctx)
{
	if (!ctx)
		return;

	pthread_join(ctx->pid, NULL);
}
