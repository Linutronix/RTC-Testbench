/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2024 Intel Corporation.
 * Author Walfred Tedeschi <walfred.tedeschi@intel.com>
 */

#ifndef _LOG_MQTT_H_
#define _LOG_MQTT_H_

struct statistics;
enum stat_frame_type;

struct log_mqtt_thread_context {
	pthread_t mqtt_log_task_id;
	struct mosquitto *mosq;
	struct ring_buffer *mqtt_log_ring_buffer;
	unsigned char *mqtt_log_data;
	volatile int stop;
};

struct log_mqtt_thread_context *log_mqtt_thread_create(void);
void log_mqtt_stats(enum stat_frame_type frame_type, struct statistics *stats);
void log_mqtt_thread_stop(struct log_mqtt_thread_context *thread_context);
void log_mqtt_thread_free(struct log_mqtt_thread_context *thread_context);
void log_mqtt_thread_wait_for_finish(struct log_mqtt_thread_context *thread_context);

void log_mqtt_free(void);

#endif /* _LOG_MQTT_H_ */
