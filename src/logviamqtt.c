// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2024 Intel Corporation.
 * Author Walfred Tedeschi <walfred.tedeschi@intel.com>
 * Copyright (C) 2025 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "app_config.h"
#ifdef WITH_MQTT
#include <mosquitto.h>
#endif

#include "config.h"
#include "logviamqtt.h"
#include "ring_buffer.h"
#include "stat.h"
#include "thread.h"
#include "utils.h"

#define LOGVIAMQTT_BUFFER_SIZE (8 * 1024)

#ifndef WITH_MQTT
struct log_via_mqtt_thread_context *log_via_mqtt_thread_create(void)
{
	return NULL;
}

void log_via_mqtt_thread_wait_for_finish(struct log_via_mqtt_thread_context *thread_context)
{
}

void log_via_mqtt_thread_free(struct log_via_mqtt_thread_context *thread_context)
{
}

void log_via_mqtt_free(void)
{
}

#else

static struct statistics statistics_per_period[NUM_FRAME_TYPES];

int log_via_mqtt_init(void)
{
	return 0;
}

static void log_via_mqtt_add_traffic_class(struct mosquitto *mosq, const char *mqtt_base_topic_name,
					   struct statistics *stat, const char *name)
{
	char stat_message[2048] = {}, *p;
	size_t stat_message_length;
	int written, result_pub;
	uint64_t time_ns;

	stat_message_length = sizeof(stat_message) - 1;
	p = stat_message;

	time_ns = stat->time_stamp;
	written = snprintf(p, stat_message_length,
			   "{\"%s\" :\n"
			   "\t{\"Timestamp\" : %" PRIu64 ",\n"
			   "\t \"MeasurementName\" : \"%s\"",
			   "reference", time_ns, mqtt_base_topic_name);

	p += written;
	stat_message_length -= written;

	written = snprintf(p, stat_message_length,
			   ",\n\t\t\"%s\" : \n\t\t{\n"
			   "\t\t\t\"TCName\" : \"%s\",\n"
			   "\t\t\t\"FramesSent\" : %" PRIu64 ",\n"
			   "\t\t\t\"FramesReceived\" : %" PRIu64 ",\n"
			   "\t\t\t\"RoundTripTimeMin\" : %" PRIu64 ",\n"
			   "\t\t\t\"RoundTripMax\" : %" PRIu64 ",\n"
			   "\t\t\t\"RoundTripAv\" : %lf,\n"
			   "\t\t\t\"OnewayMin\" : %" PRIu64 ",\n"
			   "\t\t\t\"OnewayMax\" : %" PRIu64 ",\n"
			   "\t\t\t\"OnewayAv\" : %lf,\n"
			   "\t\t\t\"DeviceLatencyMin\" : %" PRIu64 ",\n"
			   "\t\t\t\"DeviceLatencyMax\" : %" PRIu64 ",\n"
			   "\t\t\t\"DeviceLatencyAv\" : %lf,\n"
			   "\t\t\t\"RxMin\" : %" PRIu64 ",\n"
			   "\t\t\t\"RxMax\" : %" PRIu64 ",\n"
			   "\t\t\t\"RxAv\" : %lf,\n"
			   "\t\t\t\"RxHw2XdpMin\" : %" PRIu64 ",\n"
			   "\t\t\t\"RxHw2XdpMax\" : %" PRIu64 ",\n"
			   "\t\t\t\"RxHw2XdpAv\" : %lf,\n"
			   "\t\t\t\"RxXdp2AppMin\" : %" PRIu64 ",\n"
			   "\t\t\t\"RxXdp2AppMax\" : %" PRIu64 ",\n"
			   "\t\t\t\"RxXdp2AppAv\" : %lf,\n"
			   "\t\t\t\"RxWorkloadMin\" : %" PRIu64 ",\n"
			   "\t\t\t\"RxWorkloadMax\" : %" PRIu64 ",\n"
			   "\t\t\t\"RxWorkloadAv\" : %lf,\n"
			   "\t\t\t\"TxMin\" : %" PRIu64 ",\n"
			   "\t\t\t\"TxMax\" : %" PRIu64 ",\n"
			   "\t\t\t\"TxAv\" : %lf,\n"
			   "\t\t\t\"TxHwTimestampMissing\" : %" PRIu64 ",\n"
			   "\t\t\t\"OutofOrderErrors\" : %" PRIu64 ",\n"
			   "\t\t\t\"FrameIdErrors\" : %" PRIu64 ",\n"
			   "\t\t\t\"PayloadErrors\" : %" PRIu64 ",\n"
			   "\t\t\t\"RoundTripOutliers\" : %" PRIu64 ",\n"
			   "\t\t\t\"OnewayOutliers\" : %" PRIu64 "\n\t\t}",
			   "stats", name, stat->frames_sent, stat->frames_received,
			   stat->round_trip_min, stat->round_trip_max, stat->round_trip_avg,
			   stat->oneway_min, stat->oneway_max, stat->oneway_avg,
			   stat->device_latency_min, stat->device_latency_max,
			   stat->device_latency_avg, stat->rx_min, stat->rx_max, stat->rx_avg,
			   stat->rx_hw2xdp_min, stat->rx_hw2xdp_max, stat->rx_hw2xdp_avg,
			   stat->rx_xdp2app_min, stat->rx_xdp2app_max, stat->rx_xdp2app_avg,
			   stat->rx_workload_min, stat->rx_workload_max, stat->rx_workload_avg,
			   stat->tx_min, stat->tx_max, stat->tx_avg, stat->tx_hw_timestamp_missing,
			   stat->out_of_order_errors, stat->frame_id_errors, stat->payload_errors,
			   stat->round_trip_outliers, stat->oneway_outliers);

	p += written;
	stat_message_length -= written;

	written = snprintf(p, stat_message_length, "\t\t\n}\t\n}\n");

	p += written;
	stat_message_length -= written;

	result_pub = mosquitto_publish(mosq, NULL, "testbench", strlen(stat_message), stat_message,
				       2, false);
	if (result_pub != MOSQ_ERR_SUCCESS)
		fprintf(stderr, "Error publishing: %s\n", mosquitto_strerror(result_pub));
}

static void log_via_mqtt_on_connect(struct mosquitto *mosq, void *obj, int reason_code)
{
	if (reason_code != 0)
		mosquitto_disconnect(mosq);
}

static void *log_via_mqtt_thread_routine(void *data)
{
	uint64_t period_ns = app_config.stats_collection_interval_ns;
	struct log_via_mqtt_thread_context *mqtt_context = data;
	int ret, connect_status;
	struct timespec time;

	mosquitto_lib_init();

	mqtt_context->mosq = mosquitto_new(NULL, true, NULL);
	if (mqtt_context->mosq == NULL) {
		fprintf(stderr, "MQTTLog Error: Out of memory.\n");
		goto err_mqtt_outof_memory;
	}

	connect_status = mosquitto_connect(mqtt_context->mosq, app_config.log_via_mqtt_broker_ip,
					   app_config.log_via_mqtt_broker_port,
					   app_config.log_via_mqtt_keep_alive_secs);
	if (connect_status != MOSQ_ERR_SUCCESS) {
		fprintf(stderr, "MQTTLog Error by connect: %s\n",
			mosquitto_strerror(connect_status));
		goto err_mqtt_connect;
	}

	mosquitto_connect_callback_set(mqtt_context->mosq, log_via_mqtt_on_connect);

	ret = mosquitto_loop_start(mqtt_context->mosq);
	if (ret != MOSQ_ERR_SUCCESS) {
		fprintf(stderr, "Log Via MQTT Error: %s\n", mosquitto_strerror(ret));
		goto err_mqtt_start;
	}

	/*
	 * Send the statistics periodically to the MQTT broker.  This thread can run with low
	 * priority to not influence to Application Tasks that much.
	 */
	ret = clock_gettime(app_config.application_clock_id, &time);
	if (ret) {
		fprintf(stderr, "Log Via MQTT: clock_gettime() failed: %s!", strerror(errno));
		goto err_time;
	}

	while (!mqtt_context->stop) {
		int i;

		increment_period(&time, period_ns);
		ret = clock_nanosleep(app_config.application_clock_id, TIMER_ABSTIME, &time, NULL);
		if (ret) {
			pthread_error(ret, "clock_nanosleep() failed");
			goto err_time;
		}

		/* Get latest statistics data */
		stat_get_stats_per_period(statistics_per_period, sizeof(statistics_per_period));

		/* Publish via MQTT */
		for (i = 0; i < NUM_FRAME_TYPES; i++) {
			if (config_is_traffic_class_active(stat_frame_type_to_string(i)))
				log_via_mqtt_add_traffic_class(
					mqtt_context->mosq,
					app_config.log_via_mqtt_measurement_name,
					&statistics_per_period[i], stat_frame_type_to_string(i));
		}
	}

	return NULL;

err_mqtt_outof_memory:
err_mqtt_connect:
err_mqtt_start:
err_time:
	if (mqtt_context->mosq)
		mosquitto_destroy(mqtt_context->mosq);
	mosquitto_lib_cleanup();
	return NULL;
}

struct log_via_mqtt_thread_context *log_via_mqtt_thread_create(void)
{
	struct log_via_mqtt_thread_context *mqtt_context;
	int init_val, ret = 0;

	if (!app_config.log_via_mqtt)
		return NULL;

	mqtt_context = calloc(1, sizeof(*mqtt_context));
	if (!mqtt_context)
		return NULL;

	init_val = log_via_mqtt_init();
	if (init_val != 0)
		goto err_thread;

	ret = create_rt_thread(&mqtt_context->mqtt_log_task_id, "LoggerGraph",
			       app_config.log_via_mqtt_thread_priority,
			       app_config.log_via_mqtt_thread_cpu, log_via_mqtt_thread_routine,
			       mqtt_context);

	if (ret)
		goto err_thread;

	return mqtt_context;

err_thread:
	free(mqtt_context);
	return NULL;
}

void log_via_mqtt_thread_free(struct log_via_mqtt_thread_context *thread_context)
{
	if (!thread_context)
		return;

	if (app_config.log_via_mqtt) {
		if (thread_context->mosq)
			mosquitto_destroy(thread_context->mosq);
		mosquitto_lib_cleanup();
	}

	free(thread_context);
}

void log_via_mqtt_thread_stop(struct log_via_mqtt_thread_context *thread_context)
{
	if (!thread_context)
		return;

	thread_context->stop = 1;
	pthread_join(thread_context->mqtt_log_task_id, NULL);
}

void log_via_mqtt_free(void)
{
}

void log_via_mqtt_thread_wait_for_finish(struct log_via_mqtt_thread_context *thread_context)
{
	if (!thread_context)
		return;

	pthread_join(thread_context->mqtt_log_task_id, NULL);
}
#endif
