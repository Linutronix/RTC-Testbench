/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2021-2026 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#ifndef _TSN_THREAD_H_
#define _TSN_THREAD_H_

struct thread_context;

int tsn_high_threads_create(struct thread_context *thread_context);
void tsn_high_threads_free(struct thread_context *thread_context);
void tsn_high_threads_wait_for_finish(struct thread_context *thread_context);

int tsn_low_threads_create(struct thread_context *thread_context);
void tsn_low_threads_free(struct thread_context *thread_context);
void tsn_low_threads_wait_for_finish(struct thread_context *thread_context);

#endif /* _TSN_THREAD_H_ */
