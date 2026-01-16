// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2020-2025 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "config.h"
#include "log.h"
#include "stat.h"
#include "thread.h"
#include "utils.h"

static struct statistics global_statistics[NUM_FRAME_TYPES];
static struct ring_buffer *global_log_ring_buffer;
static enum log_level current_log_level;
static FILE *file_tracing_on;

int log_init(void)
{
	global_log_ring_buffer = ring_buffer_allocate(LOG_BUFFER_SIZE);

	if (!global_log_ring_buffer)
		return -ENOMEM;

	/* Default */
	current_log_level = LOG_LEVEL_DEBUG;

	if (!strcmp(app_config.log_level, "Debug"))
		current_log_level = LOG_LEVEL_DEBUG;
	if (!strcmp(app_config.log_level, "Info"))
		current_log_level = LOG_LEVEL_INFO;
	if (!strcmp(app_config.log_level, "Warning"))
		current_log_level = LOG_LEVEL_WARNING;
	if (!strcmp(app_config.log_level, "Error"))
		current_log_level = LOG_LEVEL_ERROR;

	if (app_config.debug_stop_trace_on_error) {
		file_tracing_on = fopen("/sys/kernel/tracing/tracing_on", "w");
		if (!file_tracing_on)
			return -errno;
	}

	return 0;
}

void log_free(void)
{
	ring_buffer_free(global_log_ring_buffer);

	if (app_config.debug_stop_trace_on_error)
		fclose(file_tracing_on);
}

static const char *log_level_to_string(enum log_level level)
{
	if (level == LOG_LEVEL_DEBUG)
		return "DEBUG";
	if (level == LOG_LEVEL_INFO)
		return "INFO";
	if (level == LOG_LEVEL_WARNING)
		return "WARNING";
	if (level == LOG_LEVEL_ERROR)
		return "ERROR";

	return NULL;
}

void log_message(enum log_level level, const char *format, ...)
{
	unsigned char buffer[4096];
	int written, len, ret;
	struct timespec time;
	va_list args;
	char *p;

	/* Stop trace on error if desired. */
	if (level == LOG_LEVEL_ERROR && app_config.debug_stop_trace_on_error)
		fprintf(file_tracing_on, "0\n");

	/* Log message only if log level fulfilled. */
	if (level > current_log_level)
		return;

	/* Log each message with time stamps. */
	ret = clock_gettime(app_config.application_clock_id, &time);
	if (ret)
		memset(&time, '\0', sizeof(time));

	len = sizeof(buffer) - 1;
	p = (char *)buffer;

	written = snprintf(p, len, "[%8ld.%9ld]: [%s]: ", time.tv_sec, time.tv_nsec,
			   log_level_to_string(level));
	p += written;
	len -= written;

	va_start(args, format);
	written += vsnprintf(p, len, format, args);
	va_end(args);

	ring_buffer_add(global_log_ring_buffer, buffer, written);
}

static void log_add_traffic_class(const char *name, enum stat_frame_type frame_type, char **buffer,
				  size_t *length)
{
	const struct statistics *stat = &global_statistics[frame_type];
	int written;

	written = snprintf(
		*buffer, *length,
		"%sSent=%" PRIu64 " | %sReceived=%" PRIu64 " | %sRttMin=%" PRIu64
		" [us] | %sRttMax=%" PRIu64 " [us] | %sRttAvg=%lf [us] | %sOnewayMin=%" PRIu64
		" [us] | %sOnewayMax=%" PRIu64 " [us] | %sOnewayAvg=%lf [us] | ",
		name, stat->frames_sent, name, stat->frames_received, name, stat->round_trip_min,
		name, stat->round_trip_max, name, stat->round_trip_avg, name, stat->oneway_min,
		name, stat->oneway_max, name, stat->oneway_avg);

	*buffer += written;
	*length -= written;

	if (app_config.classes[frame_type].tx_hwtstamp_enabled && config_have_rx_timestamp() &&
	    app_config.classes[frame_type].xdp_enabled && stat->proc_first_count > 0) {
		written = snprintf(*buffer, *length,
				   "%sProcFirstMin=%" PRIu64 " [us] | %sProcFirstMax=%" PRIu64
				   " [us] | %sProcFirstAvg=%lf [us] | "
				   "%sProcFirstOutliers=%" PRIu64 " | ",
				   name, stat->proc_first_min, name, stat->proc_first_max, name,
				   stat->proc_first_avg, name, stat->proc_first_outliers);
		*buffer += written;
		*length -= written;
	}

	if (app_config.classes[frame_type].tx_hwtstamp_enabled && config_have_rx_timestamp() &&
	    app_config.classes[frame_type].xdp_enabled && stat->proc_batch_count > 0) {
		written = snprintf(*buffer, *length,
				   "%sProcBatchMin=%" PRIu64 " [us] | %sProcBatchMax=%" PRIu64
				   " [us] | %sProcBatchAvg=%lf [us] | "
				   "%sProcBatchOutliers=%" PRIu64 " | ",
				   name, stat->proc_batch_min, name, stat->proc_batch_max, name,
				   stat->proc_batch_avg, name, stat->proc_batch_outliers);
		*buffer += written;
		*length -= written;
	}

	if (config_have_rx_timestamp() && app_config.classes[frame_type].xdp_enabled) {
		written = snprintf(*buffer, *length,
				   "%sRxMin=%" PRIu64 " [us] | %sRxMax=%" PRIu64
				   " [us] | %sRxAvg=%lf [us] | "
				   "%sRxHw2XdpMin=%" PRIu64 " [us] | %sRxHw2XdpMax=%" PRIu64
				   " [us] | %sRxHw2XdpAvg=%lf [us] | "
				   "%sRxXdp2AppMin=%" PRIu64 " [us] | %sRxXdp2AppMax=%" PRIu64
				   " [us] | %sRxXdp2AppAvg=%lf [us] | ",
				   name, stat->rx_min, name, stat->rx_max, name, stat->rx_avg, name,
				   stat->rx_hw2xdp_min, name, stat->rx_hw2xdp_max, name,
				   stat->rx_hw2xdp_avg, name, stat->rx_xdp2app_min, name,
				   stat->rx_xdp2app_max, name, stat->rx_xdp2app_avg);

		*buffer += written;
		*length -= written;
	}

	if (app_config.classes[frame_type].tx_hwtstamp_enabled &&
	    app_config.classes[frame_type].xdp_enabled) {
		written =
			snprintf(*buffer, *length,
				 "%sTxMin=%" PRIu64 " [us] | %sTxMax=%" PRIu64
				 " [us] | %sTxAvg=%lf [us] | %sTxHwTimestampMissing=%" PRIu64 " | ",
				 name, stat->tx_min, name, stat->tx_max, name, stat->tx_avg, name,
				 stat->tx_hw_timestamp_missing);
		*buffer += written;
		*length -= written;
	}

	if (stat_frame_type_is_real_time(frame_type)) {
		written = snprintf(*buffer, *length,
				   "%sRttOutliers=%" PRIu64 " | %sOnewayOutliers=%" PRIu64 " | ",
				   name, stat->round_trip_outliers, name, stat->oneway_outliers);
		*buffer += written;
		*length -= written;
	}

	if (app_config.classes[frame_type].rx_workload_enabled) {
		written = snprintf(*buffer, *length,
				   "%sRxWorkloadMin=%" PRIu64 " [us] | "
				   "%sRxWorkloadMax=%" PRIu64 " [us] | "
				   "%sRxWorkloadAvg=%lf [us] | "
				   "%sRxWorkloadOutliers=%" PRIu64 " | ",
				   name, stat->rx_workload_min, name, stat->rx_workload_max, name,
				   stat->rx_workload_avg, name, stat->rx_workload_outliers);

		*buffer += written;
		*length -= written;
	}
}

static void *log_thread_routine(void *data)
{
	struct log_thread_context *log_context = data;
	uint64_t period = app_config.stats_collection_interval_ns;
	struct timespec time;
	int ret;

	/*
	 * Write the content of the LogBuffer periodically to disk.  This thread can run with low
	 * priority to not influence to Application Tasks that much.
	 */
	ret = clock_gettime(app_config.application_clock_id, &time);
	if (ret) {
		fprintf(stderr, "Log: clock_gettime() failed: %s!", strerror(errno));
		return NULL;
	}

	while (!log_context->stop) {
		size_t log_data_len, stat_message_length;
		char stat_message[4096] = {}, *p;
		int i;

		/* Wait until next period */
		increment_period(&time, period);
		ret = clock_nanosleep(app_config.application_clock_id, TIMER_ABSTIME, &time, NULL);
		if (ret) {
			pthread_error(ret, "clock_nanosleep() failed");
			return NULL;
		}

		/* Get latest statistics data */
		stat_get_global_stats(global_statistics, sizeof(global_statistics));

		/* Log statistics once per logging period. */
		p = stat_message;
		stat_message_length = sizeof(stat_message) - 1;

		for (i = 0; i < NUM_FRAME_TYPES; i++) {
			if (config_is_traffic_class_active(stat_frame_type_to_string(i))) {
				const char *name =
					i == GENERICL2_FRAME_TYPE
						? app_config.classes[GENERICL2_FRAME_TYPE].name
						: stat_frame_type_to_string(i);

				log_add_traffic_class(name, i, &p, &stat_message_length);
			}
		}

		log_message(LOG_LEVEL_INFO, "%s\n", stat_message);

		/* Fetch data */
		ring_buffer_fetch(log_context->log_ring_buffer, log_context->log_data,
				  LOG_BUFFER_SIZE, &log_data_len);

		/* Write down to disk */
		if (log_data_len > 0) {
			fwrite(log_context->log_data, sizeof(char), log_data_len,
			       log_context->file_handle);
			fflush(log_context->file_handle);
		}
	}

	return NULL;
}

struct log_thread_context *log_thread_create(void)
{
	struct log_thread_context *log_context;
	int ret;

	log_context = calloc(1, sizeof(*log_context));
	if (!log_context)
		return NULL;

	log_context->log_data = calloc(LOG_BUFFER_SIZE, sizeof(unsigned char));
	if (!log_context->log_data)
		goto err_log_data;

	log_context->log_ring_buffer = global_log_ring_buffer;

	log_context->file_handle = fopen(app_config.log_file, "w+");
	if (!log_context->file_handle)
		goto err_fopen;

	ret = create_rt_thread(&log_context->log_task_id, "Logger", app_config.log_thread_priority,
			       app_config.log_thread_cpu, log_thread_routine, log_context);
	if (ret)
		goto err_thread;

	return log_context;

err_thread:
	fclose(log_context->file_handle);
err_fopen:
	free(log_context->log_data);
err_log_data:
	free(log_context);

	return NULL;
}

void log_thread_stop(struct log_thread_context *thread_context)
{
	if (!thread_context)
		return;

	thread_context->stop = 1;
	pthread_join(thread_context->log_task_id, NULL);
}

void log_thread_free(struct log_thread_context *thread_context)
{
	if (!thread_context)
		return;

	free(thread_context->log_data);
	fclose(thread_context->file_handle);
	free(thread_context);
}

void log_thread_wait_for_finish(struct log_thread_context *thread_context)
{
	if (!thread_context)
		return;

	pthread_join(thread_context->log_task_id, NULL);
}
