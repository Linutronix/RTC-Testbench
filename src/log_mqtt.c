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
#include "log_mqtt.h"
#include "stat.h"
#include "thread.h"
#include "utils.h"

#ifndef WITH_MQTT
struct log_mqtt_thread_context *log_mqtt_thread_create(void)
{
	return NULL;
}

void log_mqtt_thread_wait_for_finish(struct log_mqtt_thread_context *thread_context)
{
}

void log_mqtt_thread_free(struct log_mqtt_thread_context *thread_context)
{
}

#else

static struct statistics statistics_per_period[NUM_FRAME_TYPES];

static void log_mqtt_add_traffic_class(struct mosquitto *mosq, const char *mqtt_base_topic_name,
				       struct statistics *stat, const char *tc)
{
	char stat_message[4096] = {};
	int result_pub;

	/* Convert stats to json */
	stat_to_json(stat_message, sizeof(stat_message), stat, tc, mqtt_base_topic_name);

	/* Publish */
	result_pub = mosquitto_publish(mosq, NULL, "testbench", strlen(stat_message), stat_message,
				       2, false);
	if (result_pub != MOSQ_ERR_SUCCESS)
		fprintf(stderr, "Error publishing: %s\n", mosquitto_strerror(result_pub));
}

static void log_mqtt_on_connect(struct mosquitto *mosq, void *obj, int reason_code)
{
	if (reason_code != 0)
		mosquitto_disconnect(mosq);
}

static void *log_mqtt_thread_routine(void *data)
{
	uint64_t period_ns = app_config.stats_collection_interval_ns;
	struct log_mqtt_thread_context *mqtt_context = data;
	int ret, connect_status;
	struct timespec time;

	mosquitto_lib_init();

	mqtt_context->mosq = mosquitto_new(NULL, true, NULL);
	if (mqtt_context->mosq == NULL) {
		fprintf(stderr, "MQTTLog Error: Out of memory.\n");
		goto err_mqtt_outof_memory;
	}

	connect_status = mosquitto_connect(mqtt_context->mosq, app_config.log_mqtt_broker_ip,
					   app_config.log_mqtt_broker_port,
					   app_config.log_mqtt_keep_alive_secs);
	if (connect_status != MOSQ_ERR_SUCCESS) {
		fprintf(stderr, "MQTTLog Error by connect: %s\n",
			mosquitto_strerror(connect_status));
		goto err_mqtt_connect;
	}

	mosquitto_connect_callback_set(mqtt_context->mosq, log_mqtt_on_connect);

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
				log_mqtt_add_traffic_class(
					mqtt_context->mosq, app_config.log_mqtt_measurement_name,
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

struct log_mqtt_thread_context *log_mqtt_thread_create(void)
{
	struct log_mqtt_thread_context *mqtt_context;
	int ret = 0;

	if (!app_config.log_mqtt)
		return NULL;

	mqtt_context = calloc(1, sizeof(*mqtt_context));
	if (!mqtt_context)
		return NULL;

	ret = create_rt_thread(&mqtt_context->mqtt_log_task_id, "LoggerGraph",
			       app_config.log_mqtt_thread_priority, app_config.log_mqtt_thread_cpu,
			       log_mqtt_thread_routine, mqtt_context);

	if (ret)
		goto err_thread;

	return mqtt_context;

err_thread:
	free(mqtt_context);
	return NULL;
}

void log_mqtt_thread_free(struct log_mqtt_thread_context *thread_context)
{
	if (!thread_context)
		return;

	if (app_config.log_mqtt) {
		if (thread_context->mosq)
			mosquitto_destroy(thread_context->mosq);
		mosquitto_lib_cleanup();
	}

	free(thread_context);
}

void log_mqtt_thread_stop(struct log_mqtt_thread_context *thread_context)
{
	if (!thread_context)
		return;

	thread_context->stop = 1;
	pthread_join(thread_context->mqtt_log_task_id, NULL);
}

void log_mqtt_thread_wait_for_finish(struct log_mqtt_thread_context *thread_context)
{
	if (!thread_context)
		return;

	pthread_join(thread_context->mqtt_log_task_id, NULL);
}
#endif
