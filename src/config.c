// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2020-2026 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#include <errno.h>
#include <inttypes.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yaml.h>

#include <linux/if_ether.h>

#include "config.h"
#include "net_def.h"
#include "security.h"
#include "stat.h"
#include "thread.h"
#include "utils.h"

#include "dcp_thread.h"
#include "layer2_thread.h"
#include "lldp_thread.h"
#include "rta_thread.h"
#include "rtc_thread.h"
#include "tsn_thread.h"
#include "udp_thread.h"

struct application_config app_config;

static const struct config_app_option global_options[] = {
	APP_OPTION("ApplicationClockId", application_clock_id, CONFIG_TYPE_CLOCKID),
	APP_OPTION("ApplicationBaseCycleTimeNS", application_base_cycle_time_ns, CONFIG_TYPE_TIME),
	APP_OPTION("ApplicationBaseStartTimeNS", application_base_start_time_ns, CONFIG_TYPE_TIME),
	APP_OPTION("ApplicationBaseStartOffsetNS", application_base_start_offset_ns,
		   CONFIG_TYPE_TIME),
	APP_OPTION("ApplicationTxBaseOffsetNS", application_tx_base_offset_ns, CONFIG_TYPE_TIME),
	APP_OPTION("ApplicationRxBaseOffsetNS", application_rx_base_offset_ns, CONFIG_TYPE_TIME),
	APP_STRING_OPTION("ApplicationXdpProgram", application_xdp_program),

	APP_OPTION("LogThreadPriority", log_thread_priority, CONFIG_TYPE_INT),
	APP_OPTION("LogThreadCpu", log_thread_cpu, CONFIG_TYPE_INT),
	APP_STRING_OPTION("LogFile", log_file),
	APP_STRING_OPTION("LogLevel", log_level),

	APP_OPTION("DebugStopTraceOnOutlier", debug_stop_trace_on_outlier, CONFIG_TYPE_BOOL),
	APP_OPTION("DebugStopTraceOnError", debug_stop_trace_on_error, CONFIG_TYPE_BOOL),
	APP_OPTION("DebugMonitorMode", debug_monitor_mode, CONFIG_TYPE_BOOL),
	APP_OPTION("DebugMonitorDestination", debug_monitor_destination, CONFIG_TYPE_MAC),

	APP_OPTION("StatsHistogramEnabled", stats_histogram_enabled, CONFIG_TYPE_BOOL),
	APP_OPTION("StatsHistogramMinimumNS", stats_histogram_minimum_ns, CONFIG_TYPE_TIME),
	APP_OPTION("StatsHistogramMaximumNS", stats_histogram_maximum_ns, CONFIG_TYPE_TIME),
	APP_STRING_OPTION("StatsHistogramFile", stats_histogram_file),
	APP_OPTION("StatsCollectionIntervalNS", stats_collection_interval_ns, CONFIG_TYPE_TIME),

	APP_OPTION("LogMqtt", log_mqtt, CONFIG_TYPE_BOOL),
	APP_OPTION("LogMqttThreadPriority", log_mqtt_thread_priority, CONFIG_TYPE_INT),
	APP_OPTION("LogMqttThreadCpu", log_mqtt_thread_cpu, CONFIG_TYPE_INT),
	APP_STRING_OPTION("LogMqttBrokerIP", log_mqtt_broker_ip),
	APP_OPTION("LogMqttBrokerPort", log_mqtt_broker_port, CONFIG_TYPE_INT),
	APP_OPTION("LogMqttKeepAliveSecs", log_mqtt_keep_alive_secs, CONFIG_TYPE_INT),
	APP_STRING_OPTION("LogMqttMeasurementName", log_mqtt_measurement_name),

	APP_OPTION("LogJson", log_json, CONFIG_TYPE_BOOL),
	APP_OPTION("LogJsonThreadPriority", log_json_thread_priority, CONFIG_TYPE_INT),
	APP_OPTION("LogJsonThreadCpu", log_json_thread_cpu, CONFIG_TYPE_INT),
	APP_STRING_OPTION("LogJsonHost", log_json_host),
	APP_STRING_OPTION("LogJsonPort", log_json_port),
	APP_STRING_OPTION("LogJsonMeasurementName", log_json_measurement_name),
};

static const struct config_class_option class_options[] = {
	CLASS_OPTION("Enabled", enabled, CONFIG_TYPE_BOOL, TC_ALL),

	/* XDP options */
	CLASS_OPTION("XdpEnabled", xdp_enabled, CONFIG_TYPE_BOOL, TC_XDP),
	CLASS_OPTION("XdpSkbMode", xdp_skb_mode, CONFIG_TYPE_BOOL, TC_XDP),
	CLASS_OPTION("XdpZcMode", xdp_zc_mode, CONFIG_TYPE_BOOL, TC_XDP),
	CLASS_OPTION("XdpWakeupMode", xdp_wakeup_mode, CONFIG_TYPE_BOOL, TC_XDP),
	CLASS_OPTION("XdpBusyPollMode", xdp_busy_poll_mode, CONFIG_TYPE_BOOL, TC_XDP),
	CLASS_OPTION("TxTimeStampEnabled", tx_hwtstamp_enabled, CONFIG_TYPE_BOOL, TC_XDP),

	/* TxTime options */
	CLASS_OPTION("TxTimeEnabled", tx_time_enabled, CONFIG_TYPE_BOOL, TC_TXTIME),
	CLASS_OPTION("TxTimeOffsetNS", tx_time_offset_ns, CONFIG_TYPE_TIME, TC_TXTIME),

	/* Generic options */
	CLASS_OPTION("IgnoreRxErrors", ignore_rx_errors, CONFIG_TYPE_BOOL, TC_ALL),
	CLASS_OPTION("Vid", vid, CONFIG_TYPE_INT, TC_ALL),
	CLASS_OPTION("Pcp", pcp, CONFIG_TYPE_INT, TC_ALL),
	CLASS_OPTION("NumFramesPerCycle", num_frames_per_cycle, CONFIG_TYPE_SIZE, TC_ALL),
	CLASS_PAYLOAD_OPTION("PayloadPattern", payload_pattern, TC_ALL),
	CLASS_OPTION("FrameLength", frame_length, CONFIG_TYPE_SIZE, TC_ALL),
	CLASS_OPTION("RxQueue", rx_queue, CONFIG_TYPE_INT, TC_ALL),
	CLASS_OPTION("TxQueue", tx_queue, CONFIG_TYPE_INT, TC_ALL),
	CLASS_OPTION("SocketPriority", socket_priority, CONFIG_TYPE_INT, TC_ALL),
	CLASS_OPTION("TxThreadPriority", tx_thread_priority, CONFIG_TYPE_INT, TC_ALL),
	CLASS_OPTION("RxThreadPriority", rx_thread_priority, CONFIG_TYPE_INT, TC_ALL),
	CLASS_OPTION("TxThreadCpu", tx_thread_cpu, CONFIG_TYPE_INT, TC_ALL),
	CLASS_OPTION("RxThreadCpu", rx_thread_cpu, CONFIG_TYPE_INT, TC_ALL),
	CLASS_OPTION("Interface", interface, CONFIG_TYPE_INTERFACE, TC_ALL),

	/* Burst options */
	CLASS_OPTION("BurstPeriodNS", burst_period_ns, CONFIG_TYPE_TIME, TC_BURST),

	/* L2 options */
	CLASS_OPTION("Destination", l2_destination, CONFIG_TYPE_MAC, TC_L2),

	/* L3 options */
	CLASS_STRING_OPTION("Destination", l3_destination, TC_L3),
	CLASS_STRING_OPTION("Source", l3_source, TC_L3),
	CLASS_STRING_OPTION("Port", l3_port, TC_L3),

	/* GenericL2 */
	CLASS_STRING_OPTION("Name", name, BIT(GENERICL2_FRAME_TYPE)),
	CLASS_OPTION("EtherType", ether_type, CONFIG_TYPE_ETHER_TYPE, BIT(GENERICL2_FRAME_TYPE)),
	CLASS_OPTION("ProtocolType", protocol_type, CONFIG_TYPE_PROTOCOL_TYPE,
		     BIT(GENERICL2_FRAME_TYPE)),

	/* Security options */
	CLASS_OPTION("SecurityMode", security_mode, CONFIG_TYPE_SECURITY_MODE, TC_SECURITY),
	CLASS_OPTION("SecurityAlgorithm", security_algorithm, CONFIG_TYPE_SECURITY_ALGORITHM,
		     TC_SECURITY),
	CLASS_STRING_OPTION("SecurityKey", security_key, TC_SECURITY),
	CLASS_STRING_OPTION("SecurityIvPrefix", security_iv_prefix, TC_SECURITY),

	/* Workload options */
	CLASS_OPTION("RxWorkloadEnabled", rx_workload_enabled, CONFIG_TYPE_BOOL, TC_WORKLOAD),
	CLASS_OPTION("RxWorkloadPrewarm", rx_workload_prewarm, CONFIG_TYPE_BOOL, TC_WORKLOAD),
	CLASS_OPTION("RxWorkloadSkipCount", rx_workload_skip_count, CONFIG_TYPE_ULONG, TC_WORKLOAD),
	CLASS_STRING_OPTION("RxWorkloadFile", workload_file, TC_WORKLOAD),
	CLASS_STRING_OPTION("RxWorkloadSetupFunction", workload_setup_function, TC_WORKLOAD),
	CLASS_STRING_OPTION("RxWorkloadSetupArguments", workload_setup_arguments, TC_WORKLOAD),
	CLASS_STRING_OPTION("RxWorkloadTeardownFunction", workload_teardown_function, TC_WORKLOAD),
	CLASS_STRING_OPTION("RxWorkloadFunction", workload_function, TC_WORKLOAD),
	CLASS_STRING_OPTION("RxWorkloadArguments", workload_arguments, TC_WORKLOAD),
	CLASS_CPU_LIST_OPTION("RxWorkloadThreadCpu", workload_thread_cpus, TC_WORKLOAD),
	CLASS_OPTION("RxWorkloadThreadPriority", workload_thread_priority, CONFIG_TYPE_INT,
		     TC_WORKLOAD),
};

static bool str_match_class(const char *opt, const char *s)
{
	return !strncmp(opt, s, strlen(s));
}

static enum stat_frame_type config_opt_to_type(const char *opt, const char **suffix)
{
	if (str_match_class(opt, "TsnHigh")) {
		*suffix = opt + strlen("TsnHigh");
		return TSN_HIGH_FRAME_TYPE;
	}

	if (str_match_class(opt, "TsnLow")) {
		*suffix = opt + strlen("TsnLow");
		return TSN_LOW_FRAME_TYPE;
	}

	if (str_match_class(opt, "Rtc")) {
		*suffix = opt + strlen("Rtc");
		return RTC_FRAME_TYPE;
	}

	if (str_match_class(opt, "Rta")) {
		*suffix = opt + strlen("Rta");
		return RTA_FRAME_TYPE;
	}

	if (str_match_class(opt, "Dcp")) {
		*suffix = opt + strlen("Dcp");
		return DCP_FRAME_TYPE;
	}

	if (str_match_class(opt, "Lldp")) {
		*suffix = opt + strlen("Lldp");
		return LLDP_FRAME_TYPE;
	}

	if (str_match_class(opt, "UdpHigh")) {
		*suffix = opt + strlen("UdpHigh");
		return UDP_HIGH_FRAME_TYPE;
	}

	if (str_match_class(opt, "UdpLow")) {
		*suffix = opt + strlen("UdpLow");
		return UDP_LOW_FRAME_TYPE;
	}

	if (str_match_class(opt, "GenericL2")) {
		*suffix = opt + strlen("GenericL2");
		return GENERICL2_FRAME_TYPE;
	}

	/* Not a traffic class option */
	return NUM_FRAME_TYPES;
}

bool config_is_tc_active(enum stat_frame_type type)
{
	if (type >= NUM_FRAME_TYPES)
		return false;

	return app_config.classes[type].enabled &&
	       app_config.classes[type].num_frames_per_cycle > 0;
}

static int config_parse_bool(const char *value, bool *ret)
{
	if (!strcmp(value, "0") || !strcasecmp(value, "false"))
		*ret = false;
	else if (!strcmp(value, "1") || !strcasecmp(value, "true"))
		*ret = true;
	else
		return -EINVAL;

	return 0;
}

static int config_parse_int(const char *value, long *ret)
{
	char *endptr;

	errno = 0;
	*ret = strtol(value, &endptr, 10);
	if (errno != 0 || endptr == value || *endptr != '\0')
		return -ERANGE;

	return 0;
}

static int config_parse_ulong(const char *value, unsigned long long *ret)
{
	char *endptr;

	errno = 0;
	*ret = strtoull(value, &endptr, 10);
	if (errno != 0 || endptr == value || *endptr != '\0')
		return -ERANGE;

	return 0;
}

static int config_parse_time(const char *value, uint64_t *ret)
{
	unsigned long long tmp;
	char *endptr;

	errno = 0;
	tmp = strtoull(value, &endptr, 10);
	if (errno != 0 || endptr == value)
		return -ERANGE;

	/* Nanoseconds without unit. */
	if (*endptr == '\0') {
		*ret = tmp;
		return 0;
	}

	/* Seconds */
	if (!strcmp(endptr, "s")) {
		if (__builtin_mul_overflow(tmp, NSEC_PER_SEC, &tmp))
			return -ERANGE;
		*ret = tmp;
		return 0;
	}

	/* Milliseconds */
	if (!strcmp(endptr, "ms")) {
		if (__builtin_mul_overflow(tmp, USEC_PER_SEC, &tmp))
			return -ERANGE;
		*ret = tmp;
		return 0;
	}

	/* Microseconds */
	if (!strcmp(endptr, "us")) {
		if (__builtin_mul_overflow(tmp, MSEC_PER_SEC, &tmp))
			return -ERANGE;
		*ret = tmp;
		return 0;
	}

	return -EINVAL;
}

static int config_parse_cpu_list(const char *value, int *array, int array_len, int *num)
{
	int ret, i = 0;
	char *tmp, *p;

	/* Make a copy for strtok() */
	tmp = strdup(value);
	if (!tmp)
		return -ENOMEM;

	p = strtok(tmp, " ,");
	while (p) {
		array[i] = atoi(p);
		if (array[i] < 0) {
			ret = -EINVAL;
			goto out;
		}
		p = strtok(NULL, " ,");
		i++;

		/* CPU list too long? */
		if (i >= array_len && p) {
			ret = -ERANGE;
			goto out;
		}
	}

	if (i == 0) {
		ret = -EINVAL;
		goto out;
	}

	*num = i;
	ret = 0;

out:
	free(tmp);
	return ret;
}

static int config_parse_clockid(const char *value, clockid_t *clock)
{
	if (!strcmp(value, "CLOCK_TAI")) {
		*clock = CLOCK_TAI;
		return 0;
	}

	if (!strcmp(value, "CLOCK_MONOTONIC")) {
		*clock = CLOCK_MONOTONIC;
		return 0;
	}

	if (!strcmp(value, "CLOCK_REALTIME")) {
		*clock = CLOCK_REALTIME;
		return 0;
	}

	if (!strncmp(value, "CLOCK_AUX", strlen("CLOCK_AUX"))) {
		int ret;
		long id;

		ret = config_parse_int(value + strlen("CLOCK_AUX"), &id);
		if (ret)
			return -EINVAL;

		if (id < 0 || id >= MAX_AUX_CLOCKS)
			return -EINVAL;

		*clock = CLOCK_AUX + id;
		return 0;
	}

	/* No valid clock id found. */
	return -EINVAL;
}

static int config_store_value(const struct config_app_option *opt, void *base, const char *key,
			      const char *value)
{
	switch (opt->type) {
	case CONFIG_TYPE_BOOL: {
		bool result;

		if (config_parse_bool(value, &result)) {
			fprintf(stderr, "The value for '%s' is invalid!\n", key);
			return -EINVAL;
		}

		*(bool *)(base + opt->offset) = result;
		break;
	}
	case CONFIG_TYPE_INT: {
		long result;

		if (config_parse_int(value, &result)) {
			fprintf(stderr, "The value for '%s' is invalid!\n", key);
			return -EINVAL;
		}

		*(int *)(base + opt->offset) = result;
		break;
	}
	case CONFIG_TYPE_ULONG: {
		unsigned long long result;

		if (config_parse_ulong(value, &result)) {
			fprintf(stderr, "The value for '%s' is invalid!\n", key);
			return -EINVAL;
		}

		*(uint64_t *)(base + opt->offset) = result;
		break;
	}
	case CONFIG_TYPE_SIZE: {
		unsigned long long result;

		if (config_parse_ulong(value, &result)) {
			fprintf(stderr, "The value for '%s' is invalid!\n", key);
			return -EINVAL;
		}

		*(size_t *)(base + opt->offset) = result;
		break;
	}
	case CONFIG_TYPE_TIME: {
		uint64_t result;

		if (config_parse_time(value, &result)) {
			fprintf(stderr, "The value for '%s' is invalid!\n", key);
			return -EINVAL;
		}

		*(uint64_t *)(base + opt->offset) = result;
		break;
	}
	case CONFIG_TYPE_PAYLOAD:
	case CONFIG_TYPE_STRING: {
		char **str = (char **)(base + opt->offset);

		/* config_set_defaults() may have set a default value. */
		free(*str);
		*str = strdup(value);

		if (!*str) {
			fprintf(stderr, "strdup() for '%s' failed!\n", key);
			return -ENOMEM;
		}

		/* Set string length */
		*(size_t *)(base + opt->length_offset) = strlen(*str);
		break;
	}
	case CONFIG_TYPE_INTERFACE: {
		char *ifname = (char *)(base + opt->offset);

		strncpy(ifname, value, IF_NAMESIZE - 1);
		break;
	}
	case CONFIG_TYPE_MAC: {
		unsigned int tmp[ETH_ALEN];
		unsigned char *mac = (unsigned char *)(base + opt->offset);
		int ret;

		ret = sscanf(value, "%x:%x:%x:%x:%x:%x", &tmp[0], &tmp[1], &tmp[2], &tmp[3],
			     &tmp[4], &tmp[5]);

		if (ret != ETH_ALEN) {
			fprintf(stderr, "Failed to parse '%s' MAC Address!\n", key);
			return -EINVAL;
		}

		for (int i = 0; i < ETH_ALEN; i++)
			mac[i] = (unsigned char)tmp[i];
		break;
	}
	case CONFIG_TYPE_ETHER_TYPE: {
		unsigned long tmp;
		char *endptr;

		errno = 0;
		tmp = strtoul(value, &endptr, 16);
		if (errno != 0 || endptr == value || *endptr != '\0') {
			fprintf(stderr, "The value for '%s' is invalid!\n", key);
			return -EINVAL;
		}

		*(unsigned int *)(base + opt->offset) = tmp;
		break;
	}
	case CONFIG_TYPE_SECURITY_MODE: {
		enum security_mode *mode = (enum security_mode *)(base + opt->offset);

		if (strcasecmp(value, "none") && strcasecmp(value, "ao") &&
		    strcasecmp(value, "ae")) {
			fprintf(stderr, "Invalid security mode specified!\n");
			return -EINVAL;
		}

		if (!strcasecmp(value, "none"))
			*mode = SECURITY_MODE_NONE;
		if (!strcasecmp(value, "ao"))
			*mode = SECURITY_MODE_AO;
		if (!strcasecmp(value, "ae"))
			*mode = SECURITY_MODE_AE;
		break;
	}
	case CONFIG_TYPE_SECURITY_ALGORITHM: {
		enum security_algorithm *algo = (enum security_algorithm *)(base + opt->offset);

		if (strcasecmp(value, "aes256-gcm") && strcasecmp(value, "aes128-gcm") &&
		    strcasecmp(value, "chacha20-poly1305")) {
			fprintf(stderr, "Invalid security algorithm specified!\n");
			return -EINVAL;
		}

		if (!strcasecmp(value, "aes256-gcm"))
			*algo = SECURITY_ALGORITHM_AES256_GCM;
		if (!strcasecmp(value, "aes128-gcm"))
			*algo = SECURITY_ALGORITHM_AES128_GCM;
		if (!strcasecmp(value, "chacha20-poly1305"))
			*algo = SECURITY_ALGORITHM_CHACHA20_POLY1305;
		break;
	}
	case CONFIG_TYPE_CPU_LIST: {
		int *cpus = (int *)(base + opt->offset);
		int *num = (int *)(base + opt->length_offset);

		if (config_parse_cpu_list(value, cpus, WORKLOAD_MAX, num)) {
			fprintf(stderr, "The value for '%s' is invalid!\n", key);
			return -EINVAL;
		}

		break;
	}
	case CONFIG_TYPE_CLOCKID: {
		clockid_t clock;

		if (config_parse_clockid(value, &clock)) {
			fprintf(stderr, "Invalid clockid specified!\n");
			return -EINVAL;
		}

		*(clockid_t *)(base + opt->offset) = clock;
		break;
	}
	case CONFIG_TYPE_PROTOCOL_TYPE: {
		enum protocol_type *proto = (enum protocol_type *)(base + opt->offset);

		if (strcasecmp(value, "L2") && strcasecmp(value, "EtherCAT")) {
			fprintf(stderr, "Invalid protocol type specified!\n");
			return -EINVAL;
		}

		if (!strcasecmp(value, "L2"))
			*proto = GENERICL2_PROTOCOL_TYPE;
		if (!strcasecmp(value, "EtherCAT"))
			*proto = ETHERCAT_PROTOCOL_TYPE;
		break;
	}
	default:
		fprintf(stderr, "BUG: Unknown option detected!\n");
		return -EINVAL;
	}

	return 0;
}

static int config_store_class_option(const char *key, const char *value)
{
	struct traffic_class_config *conf;
	enum stat_frame_type type;
	const char *suffix;

	type = config_opt_to_type(key, &suffix);
	if (type == NUM_FRAME_TYPES)
		return -ENOENT;

	conf = &app_config.classes[type];
	for (size_t i = 0; i < ARRAY_SIZE(class_options); i++) {
		const struct config_class_option *opt = &class_options[i];

		if (!(opt->tcs & BIT(type)))
			continue;

		if (strcmp(suffix, opt->option.name))
			continue;

		return config_store_value(&opt->option, conf, key, value);
	}

	return -ENOENT;
}

static int config_store_app_option(const char *key, const char *value)
{
	for (size_t i = 0; i < ARRAY_SIZE(global_options); i++) {
		const struct config_app_option *opt = &global_options[i];

		if (strcmp(key, opt->name))
			continue;

		return config_store_value(opt, &app_config, key, value);
	}

	return -ENOENT;
}

/* The configuration file is YAML based. Use libyaml to parse it. */
int config_read_from_file(const char *config_file)
{
	bool base_time_seen = false;
	yaml_token_t token = {};
	int ret, state_key = 0;
	yaml_parser_t parser;
	const char *value;
	char *key = NULL;
	FILE *f;

	if (!config_file)
		return -EINVAL;

	f = fopen(config_file, "r");
	if (!f) {
		perror("fopen() failed");
		return -EIO;
	}

	ret = yaml_parser_initialize(&parser);
	if (!ret) {
		ret = -EINVAL;
		fprintf(stderr, "Failed to initialize YAML parser\n");
		goto err_yaml;
	}

	yaml_parser_set_input_file(&parser, f);

	do {
		ret = yaml_parser_scan(&parser, &token);
		if (!ret) {
			ret = -EINVAL;
			fprintf(stderr, "Failed to parse YAML file!\n");
			goto err_parse;
		}

		switch (token.type) {
		case YAML_KEY_TOKEN:
			state_key = 1;
			break;
		case YAML_VALUE_TOKEN:
			state_key = 0;
			break;
		case YAML_SCALAR_TOKEN:
			value = (const char *)token.data.scalar.value;
			if (state_key) {
				/*
				 * Save key. Free any previously saved key first, e.g. a block
				 * mapping header such as 'Application'.
				 */
				free(key);
				key = strdup(value);
				if (!key) {
					ret = -ENOMEM;
					fprintf(stderr, "No memory left!\n");
					goto err_parse;
				}

				break;
			}

			if (!key)
				break;

			/* Check for class option first, otherwise it must be a global one. */
			ret = config_store_class_option(key, value);
			if (ret == -ENOENT) {
				ret = config_store_app_option(key, value);
				if (ret == -ENOENT) {
					fprintf(stderr, "Unknown option '%s' found!\n", key);
					goto err_parse;
				}
			}
			if (ret)
				goto err_parse;

			if (!strcmp(key, "ApplicationBaseStartTimeNS"))
				base_time_seen = true;

			if (key) {
				free(key);
				key = NULL;
			}

		default:
			break;
		}

		if (token.type != YAML_STREAM_END_TOKEN)
			yaml_token_delete(&token);

	} while (token.type != YAML_STREAM_END_TOKEN);

	/*
	 * Re-calculate default base start time. There is one case where this necessary:
	 *  - The user provided a different clock_id than TAI in yaml file
	 *  - The user did not provide a base time in yaml file
	 *
	 * In that case the default base time calculated by config_set_defaults() is based on
	 * TAI. That has to be re-done by using the user provided clock id.
	 */
	if (app_config.application_clock_id != CLOCK_TAI && !base_time_seen) {
		struct timespec current;

		ret = clock_gettime(app_config.application_clock_id, &current);
		if (ret) {
			fprintf(stderr, "CONFIG: clock_gettime() failed: %s!\n", strerror(errno));
			goto err_parse;
		}
		app_config.application_base_start_time_ns = (current.tv_sec + 30) * NSEC_PER_SEC;
	}

	ret = 0;

err_parse:
	free(key);
	yaml_token_delete(&token);
	yaml_parser_delete(&parser);

err_yaml:
	fclose(f);

	return ret;
}

static void config_print_separator(void)
{
	printf("-------------------------------------------------------------------"
	       "------------------------\n");
}

static void config_print_value(const struct config_app_option *opt, const void *base)
{
	switch (opt->type) {
	case CONFIG_TYPE_BOOL: {
		bool value = *(bool *)(base + opt->offset);

		printf("%s\n", value ? "True" : "False");
		break;
	}
	case CONFIG_TYPE_INT: {
		int value = *(int *)(base + opt->offset);

		printf("%d\n", value);
		break;
	}
	case CONFIG_TYPE_TIME:
	case CONFIG_TYPE_ULONG: {
		uint64_t value = *(uint64_t *)(base + opt->offset);

		printf("%" PRIu64 "\n", value);
		break;
	}
	case CONFIG_TYPE_SIZE: {
		size_t value = *(size_t *)(base + opt->offset);

		printf("%zu\n", value);
		break;
	}
	case CONFIG_TYPE_INTERFACE: {
		char *str = (char *)(base + opt->offset);

		printf("%s\n", str);
		break;
	}
	case CONFIG_TYPE_STRING: {
		char **str = (char **)(base + opt->offset);

		printf("%s\n", *str ? *str : "NULL");
		break;
	}
	case CONFIG_TYPE_PAYLOAD: {
		char **str = (char **)(base + opt->offset);
		size_t len = *(size_t *)(base + opt->length_offset);

		print_payload_pattern(*str, len);
		break;
	}
	case CONFIG_TYPE_MAC: {
		unsigned char *mac = (unsigned char *)(base + opt->offset);

		print_mac_address(mac);
		break;
	}
	case CONFIG_TYPE_ETHER_TYPE: {
		unsigned int value = *(unsigned int *)(base + opt->offset);

		printf("0x%04x\n", value);
		break;
	}
	case CONFIG_TYPE_SECURITY_MODE: {
		enum security_mode mode = *(enum security_mode *)(base + opt->offset);

		printf("%s\n", security_mode_to_string(mode));
		break;
	}
	case CONFIG_TYPE_SECURITY_ALGORITHM: {
		enum security_algorithm algo = *(enum security_algorithm *)(base + opt->offset);

		printf("%s\n", security_algorithm_to_string(algo));
		break;
	}
	case CONFIG_TYPE_CPU_LIST: {
		int *cpus = (int *)(base + opt->offset);
		int num = *(int *)(base + opt->length_offset);

		print_cpu_list(cpus, num);
		break;
	}
	case CONFIG_TYPE_CLOCKID: {
		clockid_t clock = *(clockid_t *)(base + opt->offset);

		print_clockid(clock);
		break;
	}
	case CONFIG_TYPE_PROTOCOL_TYPE: {
		enum protocol_type proto = *(enum protocol_type *)(base + opt->offset);

		printf("%s\n", proto == GENERICL2_PROTOCOL_TYPE ? "L2" : "EtherCAT");
		break;
	}
	default:
		fprintf(stderr, "BUG: Unknown option detected!\n");
	}
}

static void config_print_tcs(void)
{
	for (int i = 0; i < NUM_FRAME_TYPES; i++) {
		const struct traffic_class_config *conf = &app_config.classes[i];

		if (!config_is_tc_active(i))
			continue;

		for (size_t j = 0; j < ARRAY_SIZE(class_options); j++) {
			/*
			 * This is probably the only place in whole code base, where
			 * GenericL2 is prefered over the user configurable name ....
			 */
			const char *prefix = i == GENERICL2_FRAME_TYPE
						     ? "GenericL2"
						     : stat_frame_type_to_string(i);
			const struct config_class_option *opt = &class_options[j];

			if (!(opt->tcs & BIT(i)))
				continue;

			printf("%s%s=", prefix, opt->option.name);
			config_print_value(&opt->option, conf);
		}
		config_print_separator();
	}
}

static void config_print_globals(void)
{
	for (size_t i = 0; i < ARRAY_SIZE(global_options); i++) {
		const struct config_app_option *opt = &global_options[i];

		printf("%s=", opt->name);
		config_print_value(opt, &app_config);
	}
	config_print_separator();
}

void config_print_values(void)
{
	config_print_separator();
	config_print_globals();
	config_print_tcs();
}

/* Similar to test/profinet. */
int config_set_defaults(bool mirror_enabled)
{
	static unsigned char default_debug_montitor_destination[] = {0x44, 0x44, 0x44,
								     0x44, 0x44, 0x44};
	static unsigned char default_lldp_destination[] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e};
	static unsigned char default_destination[] = {0xa8, 0x74, 0x1d, 0x9d, 0x98, 0xd8};
	static unsigned char default_dcp_identify[] = {0x01, 0x0e, 0xcf, 0x00, 0x00, 0x00};
	static const char *default_xdp_program = "xdp_kern_profinet_vid100.o";
	static const char *default_log_mqtt_measurement_name = "reference";
	static const char *default_udp_low_destination = "192.168.1.2";
	static const char *default_payload_pattern = "Payload! :-)";
	static const char *default_log_mqtt_broker_ip = "127.0.0.1";
	static const char *default_udp_low_source = "192.168.1.1";
	static const char *default_hist_file = "histogram.txt";
	static const char *default_json_host = "localhost";
	static const char *default_udp_low_port = "6666";
	static const char *default_json_port = "58415";
	static const char *default_log_level = "Info";
	struct traffic_class_config *conf;
	struct timespec current;
	int ret = -ENOMEM;

	clock_gettime(CLOCK_TAI, &current);

	/* Application scheduling configuration */
	app_config.application_clock_id = CLOCK_TAI;
	app_config.application_base_cycle_time_ns = 1000000;
	app_config.application_base_start_time_ns = (current.tv_sec + 30) * NSEC_PER_SEC;
	app_config.application_tx_base_offset_ns = 800000;
	app_config.application_rx_base_offset_ns = 300000;
	app_config.application_xdp_program = strdup(default_xdp_program);
	if (!app_config.application_xdp_program)
		goto out;

	/* TSN High */
	conf = &app_config.classes[TSN_HIGH_FRAME_TYPE];
	conf->rx_mirror_enabled = mirror_enabled;
	conf->xdp_enabled = true;
	conf->xdp_zc_mode = true;
	conf->xdp_wakeup_mode = true;
	conf->vid = TSN_HIGH_VID_VALUE;
	conf->pcp = TSN_HIGH_PCP_VALUE;
	conf->num_frames_per_cycle = 1;
	conf->payload_pattern = strdup(default_payload_pattern);
	if (!conf->payload_pattern)
		goto out;
	conf->payload_pattern_length = strlen(conf->payload_pattern);
	conf->frame_length = 128;
	conf->security_mode = SECURITY_MODE_NONE;
	conf->security_algorithm = SECURITY_ALGORITHM_AES256_GCM;
	conf->rx_queue = 0;
	conf->tx_queue = 0;
	conf->socket_priority = 7;
	conf->tx_thread_priority = 98;
	conf->rx_thread_priority = 98;
	conf->tx_thread_cpu = 0;
	conf->rx_thread_cpu = 0;
	conf->workload_thread_priority = 80;
	strncpy(conf->interface, "enp3s0", sizeof(conf->interface) - 1);
	memcpy((void *)conf->l2_destination, default_destination, ETH_ALEN);
	conf->protocol_type = GENERICL2_PROTOCOL_TYPE;

	/* TSN Low */
	conf = &app_config.classes[TSN_LOW_FRAME_TYPE];
	conf->rx_mirror_enabled = mirror_enabled;
	conf->xdp_enabled = true;
	conf->xdp_zc_mode = true;
	conf->xdp_wakeup_mode = true;
	conf->vid = TSN_LOW_VID_VALUE;
	conf->pcp = TSN_LOW_PCP_VALUE;
	conf->num_frames_per_cycle = 1;
	conf->payload_pattern = strdup(default_payload_pattern);
	if (!conf->payload_pattern)
		goto out;
	conf->payload_pattern_length = strlen(conf->payload_pattern);
	conf->frame_length = 128;
	conf->security_mode = SECURITY_MODE_NONE;
	conf->security_algorithm = SECURITY_ALGORITHM_AES256_GCM;
	conf->rx_queue = 1;
	conf->tx_queue = 1;
	conf->socket_priority = 6;
	conf->tx_thread_priority = 97;
	conf->rx_thread_priority = 97;
	conf->tx_thread_cpu = 1;
	conf->rx_thread_cpu = 1;
	strncpy(conf->interface, "enp3s0", sizeof(conf->interface) - 1);
	memcpy((void *)conf->l2_destination, default_destination, ETH_ALEN);
	conf->protocol_type = GENERICL2_PROTOCOL_TYPE;

	/* Real Time Cyclic (RTC) */
	conf = &app_config.classes[RTC_FRAME_TYPE];
	conf->rx_mirror_enabled = mirror_enabled;
	conf->xdp_enabled = true;
	conf->xdp_zc_mode = true;
	conf->xdp_wakeup_mode = true;
	conf->vid = PROFINET_RT_VID_VALUE;
	conf->pcp = RTC_PCP_VALUE;
	conf->num_frames_per_cycle = 1;
	conf->payload_pattern = strdup(default_payload_pattern);
	if (!conf->payload_pattern)
		goto out;
	conf->payload_pattern_length = strlen(conf->payload_pattern);
	conf->frame_length = 128;
	conf->security_mode = SECURITY_MODE_NONE;
	conf->security_algorithm = SECURITY_ALGORITHM_AES256_GCM;
	conf->rx_queue = 2;
	conf->tx_queue = 2;
	conf->socket_priority = 5;
	conf->tx_thread_priority = 96;
	conf->rx_thread_priority = 96;
	conf->tx_thread_cpu = 2;
	conf->rx_thread_cpu = 2;
	conf->workload_thread_priority = 80;
	strncpy(conf->interface, "enp3s0", sizeof(conf->interface) - 1);
	memcpy((void *)conf->l2_destination, default_destination, ETH_ALEN);
	conf->protocol_type = GENERICL2_PROTOCOL_TYPE;

	/* Real Time Acyclic (RTA) */
	conf = &app_config.classes[RTA_FRAME_TYPE];
	conf->rx_mirror_enabled = mirror_enabled;
	conf->xdp_enabled = true;
	conf->xdp_wakeup_mode = true;
	conf->vid = PROFINET_RT_VID_VALUE;
	conf->pcp = RTA_PCP_VALUE;
	conf->burst_period_ns = 200000000;
	conf->num_frames_per_cycle = 1;
	conf->payload_pattern = strdup(default_payload_pattern);
	if (!conf->payload_pattern)
		goto out;
	conf->payload_pattern_length = strlen(conf->payload_pattern);
	conf->frame_length = 200;
	conf->security_mode = SECURITY_MODE_NONE;
	conf->security_algorithm = SECURITY_ALGORITHM_AES256_GCM;
	conf->rx_queue = 3;
	conf->tx_queue = 3;
	conf->socket_priority = 4;
	conf->tx_thread_priority = 95;
	conf->rx_thread_priority = 95;
	conf->tx_thread_cpu = 3;
	conf->rx_thread_cpu = 3;
	strncpy(conf->interface, "enp3s0", sizeof(conf->interface) - 1);
	memcpy((void *)conf->l2_destination, default_destination, ETH_ALEN);
	conf->protocol_type = GENERICL2_PROTOCOL_TYPE;

	/* Discovery and Configuration Protocol (DCP) */
	conf = &app_config.classes[DCP_FRAME_TYPE];
	conf->rx_mirror_enabled = mirror_enabled;
	conf->vid = PROFINET_RT_VID_VALUE;
	conf->pcp = DCP_PCP_VALUE;
	conf->burst_period_ns = 2000000000;
	conf->num_frames_per_cycle = 1;
	conf->payload_pattern = strdup(default_payload_pattern);
	if (!conf->payload_pattern)
		goto out;
	conf->payload_pattern_length = strlen(conf->payload_pattern);
	conf->frame_length = 200;
	conf->security_mode = SECURITY_MODE_NONE;
	conf->security_algorithm = SECURITY_ALGORITHM_AES256_GCM;
	conf->rx_queue = 3;
	conf->tx_queue = 3;
	conf->socket_priority = 3;
	conf->tx_thread_priority = 94;
	conf->rx_thread_priority = 94;
	conf->tx_thread_cpu = 4;
	conf->rx_thread_cpu = 4;
	strncpy(conf->interface, "enp3s0", sizeof(conf->interface) - 1);
	memcpy((void *)conf->l2_destination, default_dcp_identify, ETH_ALEN);
	conf->protocol_type = GENERICL2_PROTOCOL_TYPE;

	/* Link Layer Discovery Protocol (LLDP) */
	conf = &app_config.classes[LLDP_FRAME_TYPE];
	conf->rx_mirror_enabled = mirror_enabled;
	conf->burst_period_ns = 5000000000;
	conf->num_frames_per_cycle = 1;
	conf->payload_pattern = strdup(default_payload_pattern);
	if (!conf->payload_pattern)
		goto out;
	conf->payload_pattern_length = strlen(conf->payload_pattern);
	conf->frame_length = 200;
	conf->security_mode = SECURITY_MODE_NONE;
	conf->security_algorithm = SECURITY_ALGORITHM_AES256_GCM;
	conf->rx_queue = 3;
	conf->tx_queue = 3;
	conf->socket_priority = 3;
	conf->tx_thread_priority = 93;
	conf->rx_thread_priority = 93;
	conf->tx_thread_cpu = 5;
	conf->rx_thread_cpu = 5;
	strncpy(conf->interface, "enp3s0", sizeof(conf->interface) - 1);
	memcpy((void *)conf->l2_destination, default_lldp_destination, ETH_ALEN);
	conf->protocol_type = GENERICL2_PROTOCOL_TYPE;

	/* User Datagram Protocol (UDP) High */
	conf = &app_config.classes[UDP_HIGH_FRAME_TYPE];
	conf->rx_mirror_enabled = mirror_enabled;
	conf->burst_period_ns = 1000000000;
	conf->num_frames_per_cycle = 1;
	conf->payload_pattern = strdup(default_payload_pattern);
	if (!conf->payload_pattern)
		goto out;
	conf->payload_pattern_length = strlen(conf->payload_pattern);
	conf->frame_length = 1400;
	conf->security_mode = SECURITY_MODE_NONE;
	conf->security_algorithm = SECURITY_ALGORITHM_AES256_GCM;
	conf->rx_queue = 3;
	conf->tx_queue = 3;
	conf->socket_priority = 3;
	conf->tx_thread_priority = 92;
	conf->rx_thread_priority = 92;
	conf->tx_thread_cpu = 6;
	conf->rx_thread_cpu = 6;
	strncpy(conf->interface, "enp3s0", sizeof(conf->interface) - 1);
	conf->l3_port = strdup(default_udp_low_port);
	if (!conf->l3_port)
		goto out;
	conf->l3_destination = strdup(default_udp_low_destination);
	if (!conf->l3_destination)
		goto out;
	conf->l3_source = strdup(default_udp_low_source);
	if (!conf->l3_source)
		goto out;
	conf->protocol_type = GENERICL2_PROTOCOL_TYPE;

	/* User Datagram Protocol (UDP) Low */
	conf = &app_config.classes[UDP_LOW_FRAME_TYPE];
	conf->rx_mirror_enabled = mirror_enabled;
	conf->burst_period_ns = 1000000000;
	conf->num_frames_per_cycle = 1;
	conf->payload_pattern = strdup(default_payload_pattern);
	if (!conf->payload_pattern)
		goto out;
	conf->payload_pattern_length = strlen(conf->payload_pattern);
	conf->frame_length = 1400;
	conf->security_mode = SECURITY_MODE_NONE;
	conf->security_algorithm = SECURITY_ALGORITHM_AES256_GCM;
	conf->rx_queue = 3;
	conf->tx_queue = 3;
	conf->socket_priority = 3;
	conf->tx_thread_priority = 91;
	conf->rx_thread_priority = 91;
	conf->tx_thread_cpu = 5;
	conf->rx_thread_cpu = 5;
	strncpy(conf->interface, "enp3s0", sizeof(conf->interface) - 1);
	conf->l3_port = strdup(default_udp_low_port);
	if (!conf->l3_port)
		goto out;
	conf->l3_destination = strdup(default_udp_low_destination);
	if (!conf->l3_destination)
		goto out;
	conf->l3_source = strdup(default_udp_low_source);
	if (!conf->l3_source)
		goto out;
	conf->protocol_type = GENERICL2_PROTOCOL_TYPE;

	/* Generic L2 */
	conf = &app_config.classes[GENERICL2_FRAME_TYPE];
	conf->name = strdup("GenericL2");
	if (!conf->name)
		goto out;
	conf->rx_mirror_enabled = mirror_enabled;
	conf->xdp_wakeup_mode = true;
	conf->vid = 100;
	conf->pcp = 6;
	conf->ether_type = 0xb62c;
	conf->num_frames_per_cycle = 1;
	conf->payload_pattern = strdup(default_payload_pattern);
	if (!conf->payload_pattern)
		goto out;
	conf->payload_pattern_length = strlen(conf->payload_pattern);
	conf->frame_length = 128;
	conf->security_mode = SECURITY_MODE_NONE;
	conf->security_algorithm = SECURITY_ALGORITHM_AES256_GCM;
	conf->rx_queue = 0;
	conf->tx_queue = 0;
	conf->socket_priority = 1;
	conf->tx_thread_priority = 90;
	conf->rx_thread_priority = 90;
	conf->tx_thread_cpu = 0;
	conf->rx_thread_cpu = 0;
	conf->workload_thread_priority = 80;
	strncpy(conf->interface, "enp3s0", sizeof(conf->interface) - 1);
	memcpy((void *)conf->l2_destination, default_destination, ETH_ALEN);
	conf->protocol_type = GENERICL2_PROTOCOL_TYPE;

	/* Logging */
	app_config.log_thread_priority = 1;
	app_config.log_thread_cpu = 0;
	app_config.log_file = strdup("reference.log");
	if (!app_config.log_file)
		goto out;
	app_config.log_level = strdup(default_log_level);
	if (!app_config.log_level)
		goto out;

	/* Debug */
	memcpy((void *)app_config.debug_monitor_destination, default_debug_montitor_destination,
	       ETH_ALEN);

	/* Stats */
	app_config.stats_histogram_minimum_ns = 1 * 1e6;
	app_config.stats_histogram_maximum_ns = 10 * 1e6;
	app_config.stats_histogram_file = strdup(default_hist_file);
	if (!app_config.stats_histogram_file)
		goto out;
	app_config.stats_histogram_file_length = strlen(default_hist_file);
	app_config.stats_collection_interval_ns = 1e9;

	/* LogMqtt */
	app_config.log_mqtt_broker_port = 1883;
	app_config.log_mqtt_thread_priority = 1;
	app_config.log_mqtt_thread_cpu = 0;
	app_config.log_mqtt_keep_alive_secs = 60;
	app_config.log_mqtt_broker_ip = strdup(default_log_mqtt_broker_ip);
	if (!app_config.log_mqtt_broker_ip)
		goto out;
	app_config.log_mqtt_measurement_name = strdup(default_log_mqtt_measurement_name);
	if (!app_config.log_mqtt_measurement_name)
		goto out;

	app_config.log_json_thread_cpu = 0;
	app_config.log_json_thread_priority = 1;
	app_config.log_json_host = strdup(default_json_host);
	if (!app_config.log_json_host)
		goto out;
	app_config.log_json_port = strdup(default_json_port);
	if (!app_config.log_json_port)
		goto out;
	app_config.log_json_measurement_name = strdup(default_log_mqtt_measurement_name);
	if (!app_config.log_json_measurement_name)
		goto out;

	return 0;
out:
	config_free();
	return ret;
}

static bool config_check_keys(const char *traffic_class, enum security_mode mode,
			      enum security_algorithm algorithm, size_t key_len,
			      size_t iv_prefix_len)
{
	const size_t expected_key_len = algorithm == SECURITY_ALGORITHM_AES128_GCM ? 16 : 32;

	if (mode == SECURITY_MODE_NONE)
		return true;

	if (iv_prefix_len != SECURITY_IV_PREFIX_LEN) {
		fprintf(stderr, "%s IV prefix length should be %d!\n", traffic_class,
			SECURITY_IV_PREFIX_LEN);
		return false;
	}

	if (expected_key_len != key_len) {
		fprintf(stderr, "%s key length mismatch!. Have %zu expected %zu for %s!\n",
			traffic_class, key_len, expected_key_len,
			security_algorithm_to_string(algorithm));
		return false;
	}

	return true;
}

/*
 * Perform configuration sanity checks. This includes:
 *   - Traffic classes
 *   - Frame lengths
 *   - Limitations
 */
bool config_sanity_check(void)
{
	const size_t min_secure_profinet_frame_size = sizeof(struct vlan_ethernet_header) +
						      sizeof(struct profinet_secure_header) +
						      sizeof(struct security_checksum);
	const size_t min_profinet_frame_size =
		sizeof(struct vlan_ethernet_header) + sizeof(struct profinet_rt_header);
	size_t min_frame_size;

	/* Either GenericL2 or PROFINET should be active. */
	if (config_is_tc_active(GENERICL2_FRAME_TYPE) &&
	    (config_is_tc_active(TSN_HIGH_FRAME_TYPE) || config_is_tc_active(TSN_LOW_FRAME_TYPE) ||
	     config_is_tc_active(RTC_FRAME_TYPE) || config_is_tc_active(RTA_FRAME_TYPE) ||
	     config_is_tc_active(DCP_FRAME_TYPE) || config_is_tc_active(LLDP_FRAME_TYPE) ||
	     config_is_tc_active(UDP_HIGH_FRAME_TYPE) || config_is_tc_active(UDP_LOW_FRAME_TYPE))) {
		fprintf(stderr, "Either use PROFINET or GenericL2!\n");
		fprintf(stderr, "For simulation of PROFINET and other middlewares in parallel "
				"start multiple instances of ref&mirror application(s) with "
				"different profiles!\n");
		return false;
	}

	/* Tx and Rx offset should be <= cycle time */
	if (app_config.application_rx_base_offset_ns > app_config.application_base_cycle_time_ns ||
	    app_config.application_tx_base_offset_ns > app_config.application_base_cycle_time_ns) {
		fprintf(stderr, "Application(Tx|Rx)BaseOffsetNS should be less than "
				"ApplicationBaseCycleTimeNS!\n");
		return false;
	}

	/* Frame lengths */
	if (app_config.classes[GENERICL2_FRAME_TYPE].frame_length > MAX_FRAME_SIZE ||
	    app_config.classes[GENERICL2_FRAME_TYPE].frame_length <
		    (sizeof(struct vlan_ethernet_header) + sizeof(struct generic_l2_header) +
		     app_config.classes[GENERICL2_FRAME_TYPE].payload_pattern_length)) {
		fprintf(stderr, "GenericL2FrameLength is invalid!\n");
		return false;
	}

	min_frame_size = app_config.classes[TSN_HIGH_FRAME_TYPE].security_mode == SECURITY_MODE_NONE
				 ? min_profinet_frame_size
				 : min_secure_profinet_frame_size;
	if (app_config.classes[TSN_HIGH_FRAME_TYPE].frame_length > MAX_FRAME_SIZE ||
	    app_config.classes[TSN_HIGH_FRAME_TYPE].frame_length <
		    (min_frame_size +
		     app_config.classes[TSN_HIGH_FRAME_TYPE].payload_pattern_length)) {
		fprintf(stderr, "TsnHighFrameLength is invalid!\n");
		return false;
	}

	min_frame_size = app_config.classes[TSN_LOW_FRAME_TYPE].security_mode == SECURITY_MODE_NONE
				 ? min_profinet_frame_size
				 : min_secure_profinet_frame_size;
	if (app_config.classes[TSN_LOW_FRAME_TYPE].frame_length > MAX_FRAME_SIZE ||
	    app_config.classes[TSN_LOW_FRAME_TYPE].frame_length <
		    (min_frame_size +
		     app_config.classes[TSN_LOW_FRAME_TYPE].payload_pattern_length)) {
		fprintf(stderr, "TsnLowFrameLength is invalid!\n");
		return false;
	}

	min_frame_size = app_config.classes[RTC_FRAME_TYPE].security_mode == SECURITY_MODE_NONE
				 ? min_profinet_frame_size
				 : min_secure_profinet_frame_size;
	if (app_config.classes[RTC_FRAME_TYPE].frame_length > MAX_FRAME_SIZE ||
	    app_config.classes[RTC_FRAME_TYPE].frame_length <
		    (min_frame_size + app_config.classes[RTC_FRAME_TYPE].payload_pattern_length)) {
		fprintf(stderr, "RtcFrameLength is invalid!\n");
		return false;
	}

	min_frame_size = app_config.classes[RTA_FRAME_TYPE].security_mode == SECURITY_MODE_NONE
				 ? min_profinet_frame_size
				 : min_secure_profinet_frame_size;
	if (app_config.classes[RTA_FRAME_TYPE].frame_length > MAX_FRAME_SIZE ||
	    app_config.classes[RTA_FRAME_TYPE].frame_length <
		    (min_frame_size + app_config.classes[RTA_FRAME_TYPE].payload_pattern_length)) {
		fprintf(stderr, "RtaFrameLength is invalid!\n");
		return false;
	}

	if (app_config.classes[DCP_FRAME_TYPE].frame_length > MAX_FRAME_SIZE ||
	    app_config.classes[DCP_FRAME_TYPE].frame_length <
		    (min_profinet_frame_size +
		     app_config.classes[DCP_FRAME_TYPE].payload_pattern_length)) {
		fprintf(stderr, "DcpFrameLength is invalid!\n");
		return false;
	}

	if (app_config.classes[LLDP_FRAME_TYPE].frame_length > MAX_FRAME_SIZE ||
	    app_config.classes[LLDP_FRAME_TYPE].frame_length <
		    (sizeof(struct ethhdr) + sizeof(struct reference_meta_data) +
		     app_config.classes[LLDP_FRAME_TYPE].payload_pattern_length)) {
		fprintf(stderr, "LldpFrameLength is invalid!\n");
		return false;
	}

	if (app_config.classes[UDP_HIGH_FRAME_TYPE].frame_length > MAX_FRAME_SIZE ||
	    app_config.classes[UDP_HIGH_FRAME_TYPE].frame_length <
		    (sizeof(struct reference_meta_data) +
		     app_config.classes[UDP_HIGH_FRAME_TYPE].payload_pattern_length)) {
		fprintf(stderr, "UdpHighFrameLength is invalid!\n");
		return false;
	}

	if (app_config.classes[UDP_LOW_FRAME_TYPE].frame_length > MAX_FRAME_SIZE ||
	    app_config.classes[UDP_LOW_FRAME_TYPE].frame_length <
		    (sizeof(struct reference_meta_data) +
		     app_config.classes[UDP_LOW_FRAME_TYPE].payload_pattern_length)) {
		fprintf(stderr, "UdpLowFrameLength is invalid!\n");
		return false;
	}

	/* XDP and TxLauchTime combined doesn't work */
	if (!config_have_xdp_tx_time() &&
	    ((app_config.classes[GENERICL2_FRAME_TYPE].tx_time_enabled &&
	      app_config.classes[GENERICL2_FRAME_TYPE].xdp_enabled) ||
	     (app_config.classes[TSN_HIGH_FRAME_TYPE].tx_time_enabled &&
	      app_config.classes[TSN_HIGH_FRAME_TYPE].xdp_enabled) ||
	     (app_config.classes[TSN_LOW_FRAME_TYPE].tx_time_enabled &&
	      app_config.classes[TSN_LOW_FRAME_TYPE].xdp_enabled))) {
		fprintf(stderr,
			"TxTime and XDP cannot be used at the same time on this platform!\n");
		fprintf(stderr, "Update libxdp to >= v1.5.0 support it.\n");
		return false;
	}

	if (!config_have_tx_timestamp() &&
	    ((app_config.classes[GENERICL2_FRAME_TYPE].tx_hwtstamp_enabled &&
	      app_config.classes[GENERICL2_FRAME_TYPE].xdp_enabled) ||
	     (app_config.classes[RTC_FRAME_TYPE].tx_hwtstamp_enabled &&
	      app_config.classes[RTC_FRAME_TYPE].xdp_enabled) ||
	     (app_config.classes[RTA_FRAME_TYPE].tx_hwtstamp_enabled &&
	      app_config.classes[RTA_FRAME_TYPE].xdp_enabled) ||
	     (app_config.classes[TSN_HIGH_FRAME_TYPE].tx_hwtstamp_enabled &&
	      app_config.classes[TSN_HIGH_FRAME_TYPE].xdp_enabled) ||
	     (app_config.classes[TSN_LOW_FRAME_TYPE].tx_hwtstamp_enabled &&
	      app_config.classes[TSN_LOW_FRAME_TYPE].xdp_enabled))) {
		fprintf(stderr, "XDP Tx HW Timestamp requires TX_TIMESTAMP build support!\n");
		fprintf(stderr, "Rebuild with -DTX_TIMESTAMP=ON (requires libxdp >= v1.5.2 and "
				"Linux kernel >= v6.8).\n");
		return false;
	}

	/* XDP busy polling only works beginning with Linux kernel version v5.11 */
	if (!config_have_busy_poll() &&
	    (app_config.classes[TSN_HIGH_FRAME_TYPE].xdp_busy_poll_mode ||
	     app_config.classes[TSN_LOW_FRAME_TYPE].xdp_busy_poll_mode ||
	     app_config.classes[RTC_FRAME_TYPE].xdp_busy_poll_mode ||
	     app_config.classes[RTA_FRAME_TYPE].xdp_busy_poll_mode ||
	     app_config.classes[GENERICL2_FRAME_TYPE].xdp_busy_poll_mode)) {
		fprintf(stderr, "XDP busy polling selected, but not supported!\n");
		return false;
	}

	if (!config_have_mosquitto() && app_config.log_mqtt) {
		fprintf(stderr, "Log via Mosquito enabled, but not supported!\n");
		return false;
	}

	/* Check keys and IV */
	if (!config_check_keys("TsnHigh", app_config.classes[TSN_HIGH_FRAME_TYPE].security_mode,
			       app_config.classes[TSN_HIGH_FRAME_TYPE].security_algorithm,
			       app_config.classes[TSN_HIGH_FRAME_TYPE].security_key_length,
			       app_config.classes[TSN_HIGH_FRAME_TYPE].security_iv_prefix_length))
		return false;
	if (!config_check_keys("TsnLow", app_config.classes[TSN_LOW_FRAME_TYPE].security_mode,
			       app_config.classes[TSN_LOW_FRAME_TYPE].security_algorithm,
			       app_config.classes[TSN_LOW_FRAME_TYPE].security_key_length,
			       app_config.classes[TSN_LOW_FRAME_TYPE].security_iv_prefix_length))
		return false;
	if (!config_check_keys("Rtc", app_config.classes[RTC_FRAME_TYPE].security_mode,
			       app_config.classes[RTC_FRAME_TYPE].security_algorithm,
			       app_config.classes[RTC_FRAME_TYPE].security_key_length,
			       app_config.classes[RTC_FRAME_TYPE].security_iv_prefix_length))
		return false;
	if (!config_check_keys("Rta", app_config.classes[RTA_FRAME_TYPE].security_mode,
			       app_config.classes[RTA_FRAME_TYPE].security_algorithm,
			       app_config.classes[RTA_FRAME_TYPE].security_key_length,
			       app_config.classes[RTA_FRAME_TYPE].security_iv_prefix_length))
		return false;

	/* Stats */
	if (app_config.stats_histogram_minimum_ns > app_config.stats_histogram_maximum_ns) {
		fprintf(stderr, "Histogram minimum and maximum values are invalid!\n");
		return false;
	}

	/* EtherCAT */
	if (config_is_tc_active(GENERICL2_FRAME_TYPE) &&
	    app_config.classes[GENERICL2_FRAME_TYPE].protocol_type == ETHERCAT_PROTOCOL_TYPE &&
	    app_config.classes[GENERICL2_FRAME_TYPE].frame_length <
		    sizeof(struct ethhdr) + sizeof(struct ethercat_header) + 20) {
		fprintf(stderr, "EtherCAT needs a minimum frame length of %zu!\n",
			sizeof(struct ethhdr) + sizeof(struct ethercat_header) + 20);
		return false;
	}

	return true;
}

/* Free all strings allocated with strdup(). */
void config_free(void)
{
	for (size_t i = 0; i < ARRAY_SIZE(global_options); i++) {
		const struct config_app_option *opt = &global_options[i];
		void *base = &app_config;
		char **str;

		if (!(opt->type == CONFIG_TYPE_STRING || opt->type == CONFIG_TYPE_PAYLOAD))
			continue;

		str = (char **)(base + opt->offset);
		free(*str);
	}

	for (int i = 0; i < NUM_FRAME_TYPES; i++) {
		void *base = &app_config.classes[i];

		for (size_t j = 0; j < ARRAY_SIZE(class_options); j++) {
			const struct config_class_option *opt = &class_options[j];
			char **str;

			if (!(opt->tcs & BIT(i)))
				continue;

			if (!(opt->option.type == CONFIG_TYPE_STRING ||
			      opt->option.type == CONFIG_TYPE_PAYLOAD))
				continue;

			str = (char **)(base + opt->option.offset);
			free(*str);
		}
	}
}
