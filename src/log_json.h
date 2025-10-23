/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2025 Linutronix GmbH
 */

#ifndef _LOG_JSON_H_
#define _LOG_JSON_H_

#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

struct log_json_thread_context {
	struct sockaddr_storage dest;
	pthread_t pid;
	int socket;
	volatile int stop;
};

struct log_json_thread_context *log_json_thread_create(void);
void log_json_thread_stop(struct log_json_thread_context *ctx);
void log_json_thread_free(struct log_json_thread_context *ctx);
void log_json_thread_wait_for_finish(struct log_json_thread_context *ctx);

#endif /* _LOG_JSON_H_ */
