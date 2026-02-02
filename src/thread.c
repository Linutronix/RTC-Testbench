// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2020-2026 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "thread.h"
#include "utils.h"

int create_rt_thread(pthread_t *task_id, int thread_priority, int cpu_core,
		     void *(*thread_routine)(void *), void *data, const char *format, ...)
{
	struct sched_param param;
	char thread_name[16]; /* TASK_COMM_LEN */
	pthread_attr_t attr;
	cpu_set_t cpus;
	va_list args;
	int ret;

	va_start(args, format);
	vsnprintf(thread_name, sizeof(thread_name), format, args);
	va_end(args);

	ret = pthread_attr_init(&attr);
	if (ret) {
		pthread_error(ret, "pthread_attr_init() failed");
		goto err;
	}

	/* 2 MiB stack should be enough for all threads. */
	ret = pthread_attr_setstacksize(&attr, 2 * 1024 * 1024);
	if (ret) {
		pthread_error(ret, "pthread_attr_setstacksize() failed");
		goto err;
	}

	ret = pthread_attr_setschedpolicy(&attr, SCHED_FIFO);
	if (ret) {
		pthread_error(ret, "pthread_attr_setschedpolicy() failed");
		goto err;
	}

	param.sched_priority = thread_priority;
	ret = pthread_attr_setschedparam(&attr, &param);
	if (ret) {
		pthread_error(ret, "pthread_attr_setschedparam() failed");
		goto err;
	}

	ret = pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED);
	if (ret) {
		pthread_error(ret, "pthread_attr_setinheritsched() failed");
		goto err;
	}

	CPU_ZERO(&cpus);
	CPU_SET(cpu_core, &cpus);
	ret = pthread_attr_setaffinity_np(&attr, sizeof(cpus), &cpus);
	if (ret) {
		pthread_error(ret, "pthread_attr_setaffinity_np() failed");
		goto err;
	}

	ret = pthread_create(task_id, &attr, thread_routine, data);
	if (ret) {
		pthread_error(ret, "pthread_create() failed");
		goto err;
	}

	ret = pthread_setname_np(*task_id, thread_name);
	if (ret) {
		pthread_error(ret, "pthread_setname_np() failed");
		goto err;
	}

	return 0;

err:
	return -ret;
}

void init_mutex(pthread_mutex_t *mutex)
{
	pthread_mutexattr_t mattr;

	/* Set priority inheritance protocol on this mutex. It's disabled by default. */
	pthread_mutexattr_init(&mattr);
	pthread_mutexattr_setprotocol(&mattr, PTHREAD_PRIO_INHERIT);
	pthread_mutex_init(mutex, &mattr);
}

void init_condition_variable(pthread_cond_t *cond_var)
{
	pthread_condattr_t cattr;

	pthread_condattr_init(&cattr);
	pthread_condattr_setclock(&cattr, CLOCK_MONOTONIC);
	pthread_cond_init(cond_var, &cattr);
}

static struct thread_context *find_next_pn_thread(struct thread_context *pn_threads, int start)
{
	switch (start) {
	case TSN_HIGH_THREAD:
		if (config_is_traffic_class_active("TsnLow"))
			return &pn_threads[TSN_LOW_THREAD];
	case TSN_LOW_THREAD:
		if (config_is_traffic_class_active("Rtc"))
			return &pn_threads[RTC_THREAD];
	case RTC_THREAD:
		if (config_is_traffic_class_active("Rta"))
			return &pn_threads[RTA_THREAD];
	case RTA_THREAD:
		if (config_is_traffic_class_active("Dcp"))
			return &pn_threads[DCP_THREAD];
	case DCP_THREAD:
		if (config_is_traffic_class_active("Lldp"))
			return &pn_threads[LLDP_THREAD];
	case LLDP_THREAD:
		if (config_is_traffic_class_active("UdpHigh"))
			return &pn_threads[UDP_HIGH_THREAD];
	case UDP_HIGH_THREAD:
		if (config_is_traffic_class_active("UdpLow"))
			return &pn_threads[UDP_LOW_THREAD];
	case UDP_LOW_THREAD:
		return NULL;
	}

	return NULL;
}

int link_pn_threads(struct thread_context *pn_threads)
{
	struct thread_context *t, *p;

	/*
	 * The Profinet traffic classes have a dedicated order:
	 *   TSN -> RTC -> RTA -> DCP -> LLDP -> UDP
	 *
	 * This code will link the traffic classes in order. Non-active traffic classes will be
	 * skipped.
	 */
	for (int i = 0; i < NUM_PN_THREAD_TYPES; i++) {
		struct thread_context *current = &pn_threads[i];

		current->next = find_next_pn_thread(pn_threads, i);
	}

	/*
	 * The first traffic class is either
	 *  a) TSN in case of Profinet TSN, or
	 *  b) RTC in case of Profinet RT.
	 *
	 * GenericL2 has nothing todo with Profinet.
	 */
	if (config_is_traffic_class_active("TsnHigh")) {
		pn_threads[TSN_HIGH_THREAD].is_first = true;
		t = &pn_threads[TSN_HIGH_THREAD];
	} else if (config_is_traffic_class_active("Rtc")) {
		pn_threads[RTC_THREAD].is_first = true;
		t = &pn_threads[RTC_THREAD];
	} else if (config_is_traffic_class_active("GenericL2")) {
		return 0;
	} else {
		return -EINVAL;
	}

	/* Find last PN thread. */
	while (t) {
		p = t;
		t = t->next;
	}
	p->is_last = true;

	return 0;
}
