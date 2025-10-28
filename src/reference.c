// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2020-2025 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/mman.h>

#include "app_config.h"
#include "config.h"
#include "dcp_thread.h"
#include "hist.h"
#include "layer2_thread.h"
#include "lldp_thread.h"
#include "log.h"
#include "log_json.h"
#include "log_mqtt.h"
#include "print.h"
#include "rta_thread.h"
#include "rtc_thread.h"
#include "stat.h"
#include "thread.h"
#include "tsn_thread.h"
#include "udp_thread.h"
#include "utils.h"

static struct option long_options[] = {
	{"config", optional_argument, NULL, 'c'},
	{"help", no_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'V'},
	{NULL},
};

static struct log_mqtt_thread_context *log_mqtt_thread;
static struct log_json_thread_context *log_json_thread;
static struct log_thread_context *log_thread;
static struct thread_context *g2_threads;
static struct thread_context *threads;

static void term_handler(int sig)
{
	int i;

	printf("Stopping all application threads...\n");

	print_stop = 1;

	if (log_mqtt_thread)
		log_mqtt_thread->stop = 1;

	if (log_json_thread)
		log_json_thread->stop = 1;

	if (log_thread)
		log_thread->stop = 1;

	if (g2_threads)
		g2_threads->stop = 1;

	if (threads)
		for (i = 0; i < NUM_PN_THREAD_TYPES; i++)
			threads[i].stop = 1;
}

static void reset_stats_handler(int sig)
{
	reset_stats = 1;
}

static void setup_signals(void)
{
	struct sigaction sa1, sa2;

	sigemptyset(&sa1.sa_mask);
	sa1.sa_handler = term_handler;
	sa1.sa_flags = 0;

	sigemptyset(&sa2.sa_mask);
	sa2.sa_handler = reset_stats_handler;
	sa2.sa_flags = 0;

	if (sigaction(SIGTERM, &sa1, NULL))
		perror("sigaction() failed");
	if (sigaction(SIGINT, &sa1, NULL))
		perror("sigaction() failed");
	if (sigaction(SIGUSR1, &sa2, NULL))
		perror("sigaction() failed");
}

static void print_usage_and_die(void)
{
	fprintf(stderr, "usage: reference [options]\n");
	fprintf(stderr, "  options:\n");
	fprintf(stderr, "    -h, --help:    Print this help text\n");
	fprintf(stderr, "    -V, --version: Print version\n");
	fprintf(stderr, "    -c, --config:  Path to config file\n");

	exit(EXIT_SUCCESS);
}

static void print_version_and_die(void)
{
	printf("reference: version \"%s\"\n", VERSION);
	exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
	const char *config_file = NULL;
	int c, ret;

	while ((c = getopt_long(argc, argv, "c:hV", long_options, NULL)) != -1) {
		switch (c) {
		case 'V':
			print_version_and_die();
			break;
		case 'c':
			config_file = optarg;
			break;
		case 'h':
		default:
			print_usage_and_die();
		}
	}

	ret = config_set_defaults(false);
	if (ret) {
		fprintf(stderr, "Failed to set default config values!\n");
		exit(EXIT_FAILURE);
	}

	if (!config_file) {
		fprintf(stderr, "Specifying an configuration file is mandatory. See tests/ "
				"directory for examples!\n");
		exit(EXIT_FAILURE);
	}

	ret = config_read_from_file(config_file);
	if (ret) {
		fprintf(stderr, "Failed to parse configuration file!\n");
		exit(EXIT_FAILURE);
	}

	config_print_values();

	if (!config_sanity_check()) {
		fprintf(stderr, "Configuration failed sanity checks!\n");
		exit(EXIT_FAILURE);
	}

	if (mlockall(MCL_CURRENT | MCL_FUTURE)) {
		perror("mlockall() failed");
		exit(EXIT_FAILURE);
	}

	configure_cpu_latency();

	setup_signals();

	ret = log_init();
	if (ret) {
		fprintf(stderr, "Failed to initialize logging!\n");
		exit(EXIT_FAILURE);
	}

	ret = histogram_init();
	if (ret) {
		fprintf(stderr, "Failed to initialize histogram code!\n");
		exit(EXIT_FAILURE);
	}

	ret = stat_init(LOG_REFERENCE);
	if (ret) {
		fprintf(stderr, "Failed to initialize statistics!\n");
		exit(EXIT_FAILURE);
	}

	log_thread = log_thread_create();
	if (!log_thread) {
		fprintf(stderr, "Failed to create and start Log Thread!\n");
		exit(EXIT_FAILURE);
	}

	log_mqtt_thread = log_mqtt_thread_create();
	if (!log_mqtt_thread && app_config.log_mqtt) {
		fprintf(stderr, "Failed to create and start Log via MQTT Thread!\n");
		exit(EXIT_FAILURE);
	}

	log_json_thread = log_json_thread_create();
	if (!log_json_thread && app_config.log_json) {
		fprintf(stderr, "Failed to create and start Log via JSON Thread!\n");
		exit(EXIT_FAILURE);
	}

	g2_threads = generic_l2_threads_create();
	if (!g2_threads) {
		fprintf(stderr, "Failed to create and start Generic L2 Threads!\n");
		exit(EXIT_FAILURE);
	}

	threads = calloc(NUM_PN_THREAD_TYPES, sizeof(struct thread_context));
	if (!threads) {
		fprintf(stderr, "Failed to allocate PN threads!\n");
		exit(EXIT_FAILURE);
	}

	if (link_pn_threads(threads)) {
		fprintf(stderr, "Failed to determine PN traffic classes order!\n");
		exit(EXIT_FAILURE);
	}

	ret = udp_low_threads_create(&threads[UDP_LOW_THREAD]);
	if (ret) {
		fprintf(stderr, "Failed to create and start UDP Low Threads!\n");
		exit(EXIT_FAILURE);
	}

	ret = udp_high_threads_create(&threads[UDP_HIGH_THREAD]);
	if (ret) {
		fprintf(stderr, "Failed to create and start UDP High Threads!\n");
		exit(EXIT_FAILURE);
	}

	ret = lldp_threads_create(&threads[LLDP_THREAD]);
	if (ret) {
		fprintf(stderr, "Failed to create and start LLDP Threads!\n");
		exit(EXIT_FAILURE);
	}

	ret = dcp_threads_create(&threads[DCP_THREAD]);
	if (ret) {
		fprintf(stderr, "Failed to create and start DCP Threads!\n");
		exit(EXIT_FAILURE);
	}

	ret = rta_threads_create(&threads[RTA_THREAD]);
	if (ret) {
		fprintf(stderr, "Failed to create and start RTA Threads!\n");
		exit(EXIT_FAILURE);
	}

	ret = rtc_threads_create(&threads[RTC_THREAD]);
	if (ret) {
		fprintf(stderr, "Failed to create and start RTC Threads!\n");
		exit(EXIT_FAILURE);
	}

	ret = tsn_low_threads_create(&threads[TSN_LOW_THREAD]);
	if (ret) {
		fprintf(stderr, "Failed to create and start TSN Low Threads!\n");
		exit(EXIT_FAILURE);
	}

	ret = tsn_high_threads_create(&threads[TSN_HIGH_THREAD]);
	if (ret) {
		fprintf(stderr, "Failed to create and start TSN High Threads!\n");
		exit(EXIT_FAILURE);
	}

	print_stats();

	tsn_high_threads_wait_for_finish(&threads[TSN_HIGH_THREAD]);
	tsn_low_threads_wait_for_finish(&threads[TSN_LOW_THREAD]);
	rtc_threads_wait_for_finish(&threads[RTC_THREAD]);
	rta_threads_wait_for_finish(&threads[RTA_THREAD]);
	dcp_threads_wait_for_finish(&threads[DCP_THREAD]);
	lldp_threads_wait_for_finish(&threads[LLDP_THREAD]);
	udp_high_threads_wait_for_finish(&threads[UDP_HIGH_THREAD]);
	udp_low_threads_wait_for_finish(&threads[UDP_LOW_THREAD]);
	generic_l2_threads_wait_for_finish(g2_threads);
	log_mqtt_thread_wait_for_finish(log_mqtt_thread);
	log_json_thread_wait_for_finish(log_json_thread);
	log_thread_wait_for_finish(log_thread);

	histogram_write();

	tsn_high_threads_free(&threads[TSN_HIGH_THREAD]);
	tsn_low_threads_free(&threads[TSN_LOW_THREAD]);
	rtc_threads_free(&threads[RTC_THREAD]);
	rta_threads_free(&threads[RTA_THREAD]);
	dcp_threads_free(&threads[DCP_THREAD]);
	lldp_threads_free(&threads[LLDP_THREAD]);
	udp_high_threads_free(&threads[UDP_HIGH_THREAD]);
	udp_low_threads_free(&threads[UDP_LOW_THREAD]);
	generic_l2_threads_free(g2_threads);
	log_mqtt_thread_free(log_mqtt_thread);
	log_json_thread_free(log_json_thread);
	log_thread_free(log_thread);

	histogram_free();
	stat_free();
	log_free();
	config_free();
	free(threads);

	restore_cpu_latency();

	return EXIT_SUCCESS;
}
