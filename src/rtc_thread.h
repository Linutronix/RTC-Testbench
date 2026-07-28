/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2020-2026 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#ifndef _RTC_THREAD_H_
#define _RTC_THREAD_H_

struct thread_context;

int rtc_threads_create(struct thread_context *thread_context);
void rtc_threads_free(struct thread_context *thread_context);
void rtc_threads_wait_for_finish(struct thread_context *thread_context);

#endif /* _RTC_THREAD_H_ */
