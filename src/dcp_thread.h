/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2020-2026 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#ifndef _DCP_THREAD_H_
#define _DCP_THREAD_H_

struct thread_context;

int dcp_threads_create(struct thread_context *thread_context);
void dcp_threads_free(struct thread_context *thread_context);
void dcp_threads_wait_for_finish(struct thread_context *thread_context);

#endif /* _DCP_THREAD_H_ */
