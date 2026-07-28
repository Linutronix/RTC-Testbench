/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2022-2026 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#ifndef _LAYER2_THREAD_H_
#define _LAYER2_THREAD_H_

struct thread_context;

int generic_l2_threads_create(struct thread_context *ctx);
void generic_l2_threads_free(struct thread_context *ctx);
void generic_l2_threads_wait_for_finish(struct thread_context *ctx);

#endif /* _LAYER2_THREAD_H_ */
