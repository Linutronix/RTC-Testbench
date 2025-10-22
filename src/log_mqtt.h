/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2024 Intel Corporation.
 * Author Walfred Tedeschi <walfred.tedeschi@intel.com>
 * Copyright (C) 2025 Linutronix GmbH
 */

#ifndef _LOG_MQTT_H_
#define _LOG_MQTT_H_

struct mosquitto;

struct log_mqtt_thread_context {
	pthread_t mqtt_log_task_id;
	struct mosquitto *mosq;
	volatile int stop;
};

struct log_mqtt_thread_context *log_mqtt_thread_create(void);
void log_mqtt_thread_stop(struct log_mqtt_thread_context *thread_context);
void log_mqtt_thread_free(struct log_mqtt_thread_context *thread_context);
void log_mqtt_thread_wait_for_finish(struct log_mqtt_thread_context *thread_context);

#endif /* _LOG_MQTT_H_ */
