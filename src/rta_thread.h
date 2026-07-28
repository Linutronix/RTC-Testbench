/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2020-2026 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#ifndef _RTA_THREAD_H_
#define _RTA_THREAD_H_

struct thread_context;

int rta_threads_create(struct thread_context *thread_context);
void rta_threads_free(struct thread_context *thread_context);
void rta_threads_wait_for_finish(struct thread_context *thread_context);

#endif /* _RTA_THREAD_H_ */
