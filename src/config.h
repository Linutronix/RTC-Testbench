/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2020-2026 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#ifndef _CONFIG_H_
#define _CONFIG_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include <linux/if_ether.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include "app_config.h"

#include "security.h"
#include "stat.h"

enum config_value_type {
	CONFIG_TYPE_BOOL,
	CONFIG_TYPE_INT,
	CONFIG_TYPE_ULONG,
	CONFIG_TYPE_SIZE,
	CONFIG_TYPE_TIME,
	CONFIG_TYPE_STRING,
	CONFIG_TYPE_PAYLOAD,
	CONFIG_TYPE_INTERFACE,
	CONFIG_TYPE_MAC,
	CONFIG_TYPE_ETHER_TYPE,
	CONFIG_TYPE_SECURITY_MODE,
	CONFIG_TYPE_SECURITY_ALGORITHM,
	CONFIG_TYPE_CPU_LIST,
	CONFIG_TYPE_CLOCKID,
};

#ifndef BIT
#define BIT(x) (1ULL << (x))
#endif
#define TC_ALL (BIT(NUM_FRAME_TYPES) - 1)
#define TC_TSN (BIT(TSN_HIGH_FRAME_TYPE) | BIT(TSN_LOW_FRAME_TYPE))
#define TC_UDP (BIT(UDP_HIGH_FRAME_TYPE) | BIT(UDP_LOW_FRAME_TYPE))
#define TC_PROFINET (TC_TSN | BIT(RTC_FRAME_TYPE) | BIT(RTA_FRAME_TYPE))

/* Traffic classes with XDP */
#define TC_XDP (TC_PROFINET | BIT(GENERICL2_FRAME_TYPE))

/* Traffic classes with Workload execution */
#define TC_WORKLOAD (BIT(TSN_HIGH_FRAME_TYPE) | BIT(RTC_FRAME_TYPE) | BIT(GENERICL2_FRAME_TYPE))

/* Layer 2 Traffic classes */
#define TC_L2 (TC_PROFINET | BIT(DCP_FRAME_TYPE) | BIT(LLDP_FRAME_TYPE) | BIT(GENERICL2_FRAME_TYPE))

/* Layer 3 Traffic classes */
#define TC_L3 (TC_UDP)

/* Burst Traffic classes */
#define TC_BURST (BIT(RTA_FRAME_TYPE) | BIT(DCP_FRAME_TYPE) | BIT(LLDP_FRAME_TYPE) | TC_UDP)

/* Security Traffic classes */
#define TC_SECURITY (TC_PROFINET)

/* Traffic classes with TxTime */
#define TC_TXTIME (TC_TSN | BIT(GENERICL2_FRAME_TYPE))

struct config_app_option {
	const char *name;
	enum config_value_type type;
	size_t offset;
	size_t length_offset;
};

struct config_class_option {
	struct config_app_option option;
	unsigned int tcs;
};

#define APP_OPTION(key, member, vtype)                                                             \
	{.name = key, .type = vtype, .offset = offsetof(struct application_config, member)}

#define APP_STRING_OPTION(key, member)                                                             \
	{.name = key,                                                                              \
	 .type = CONFIG_TYPE_STRING,                                                               \
	 .offset = offsetof(struct application_config, member),                                    \
	 .length_offset = offsetof(struct application_config, member##_length)}

#define CLASS_OPTION(key, member, vtype, mask)                                                     \
	{.option = {.name = key,                                                                   \
		    .type = vtype,                                                                 \
		    .offset = offsetof(struct traffic_class_config, member)},                      \
	 .tcs = mask}

#define CLASS_STRING_OPTION(key, member, mask)                                                     \
	{.option = {.name = key,                                                                   \
		    .type = CONFIG_TYPE_STRING,                                                    \
		    .offset = offsetof(struct traffic_class_config, member),                       \
		    .length_offset = offsetof(struct traffic_class_config, member##_length)},      \
	 .tcs = mask}

#define CLASS_PAYLOAD_OPTION(key, member, mask)                                                    \
	{.option = {.name = key,                                                                   \
		    .type = CONFIG_TYPE_PAYLOAD,                                                   \
		    .offset = offsetof(struct traffic_class_config, member),                       \
		    .length_offset = offsetof(struct traffic_class_config, member##_length)},      \
	 .tcs = mask}

#define CLASS_CPU_LIST_OPTION(key, member, mask)                                                   \
	{.option = {.name = key,                                                                   \
		    .type = CONFIG_TYPE_CPU_LIST,                                                  \
		    .offset = offsetof(struct traffic_class_config, member),                       \
		    .length_offset = offsetof(struct traffic_class_config, member##_num)},         \
	 .tcs = mask}

struct traffic_class_config {
	/* General */
	bool enabled;
	bool rx_mirror_enabled;
	char *name;
	size_t name_length;

	/* Network settings */
	bool xdp_enabled;
	bool xdp_skb_mode;
	bool xdp_zc_mode;
	bool xdp_wakeup_mode;
	bool xdp_busy_poll_mode;
	bool tx_time_enabled;
	bool tx_hwtstamp_enabled;
	bool ignore_rx_errors;
	uint64_t tx_time_offset_ns;
	uint64_t burst_period_ns;

	/* Traffic class settings */
	unsigned int ether_type;
	int vid;
	int pcp;
	size_t num_frames_per_cycle;
	char *payload_pattern;
	size_t payload_pattern_length;
	size_t frame_length;
	int rx_queue;
	int tx_queue;

	/* Layer 2/3 settings */
	char interface[IF_NAMESIZE];
	unsigned char l2_destination[ETH_ALEN];
	char *l3_port;
	size_t l3_port_length;
	char *l3_destination;
	size_t l3_destination_length;
	char *l3_source;
	size_t l3_source_length;

	/* Security settings */
	enum security_mode security_mode;
	enum security_algorithm security_algorithm;
	char *security_key;
	size_t security_key_length;
	char *security_iv_prefix;
	size_t security_iv_prefix_length;

	/* Operating system settings */
	int socket_priority;
	int tx_thread_priority;
	int rx_thread_priority;
	int tx_thread_cpu;
	int rx_thread_cpu;
	int workload_thread_cpus[WORKLOAD_MAX];
	int workload_thread_cpus_num;
	int workload_thread_priority;

	/* Workload settings */
	bool rx_workload_enabled;
	bool rx_workload_prewarm;
	uint64_t rx_workload_skip_count;
	char *workload_file;
	size_t workload_file_length;
	char *workload_function;
	size_t workload_function_length;
	char *workload_arguments;
	size_t workload_arguments_length;
	char *workload_setup_function;
	size_t workload_setup_function_length;
	char *workload_setup_arguments;
	size_t workload_setup_arguments_length;
	char *workload_teardown_function;
	size_t workload_teardown_function_length;
};

struct application_config {
	/* Application scheduling configuration */
	clockid_t application_clock_id;
	uint64_t application_base_cycle_time_ns;
	uint64_t application_base_start_time_ns;
	uint64_t application_base_start_offset_ns;
	uint64_t application_tx_base_offset_ns;
	uint64_t application_rx_base_offset_ns;
	char *application_xdp_program;
	size_t application_xdp_program_length;
	/* Traffic class configurations */
	struct traffic_class_config classes[NUM_FRAME_TYPES];
	/* Logging */
	int log_thread_priority;
	int log_thread_cpu;
	char *log_file;
	size_t log_file_length;
	char *log_level;
	size_t log_level_length;
	/* Debug */
	bool debug_stop_trace_on_outlier;
	bool debug_stop_trace_on_error;
	bool debug_monitor_mode;
	unsigned char debug_monitor_destination[ETH_ALEN];
	/* Statistics */
	bool stats_histogram_enabled;
	uint64_t stats_histogram_minimum_ns;
	uint64_t stats_histogram_maximum_ns;
	char *stats_histogram_file;
	size_t stats_histogram_file_length;
	uint64_t stats_collection_interval_ns;
	/* Log through MQTT */
	bool log_mqtt;
	int log_mqtt_thread_priority;
	int log_mqtt_thread_cpu;
	size_t log_mqtt_broker_ip_length;
	char *log_mqtt_broker_ip;
	int log_mqtt_broker_port;
	int log_mqtt_keep_alive_secs;
	size_t log_mqtt_measurement_name_length;
	char *log_mqtt_measurement_name;
	/* Log through JSON/UDP */
	bool log_json;
	int log_json_thread_priority;
	int log_json_thread_cpu;
	size_t log_json_host_length;
	char *log_json_host;
	size_t log_json_port_length;
	char *log_json_port;
	size_t log_json_measurement_name_length;
	char *log_json_measurement_name;
};

extern struct application_config app_config;

int config_read_from_file(const char *config_file);
int config_set_defaults(bool mirror_enabled);
void config_print_values(void);
bool config_sanity_check(void);
void config_free(void);
bool config_is_traffic_class_active(enum stat_frame_type type);

static inline bool config_have_busy_poll(void)
{
#if defined(HAVE_SO_BUSY_POLL) && defined(HAVE_SO_PREFER_BUSY_POLL) &&                             \
	defined(HAVE_SO_BUSY_POLL_BUDGET)
	return true;
#else
	return false;
#endif
}

static inline bool config_have_mosquitto(void)
{
#if defined(WITH_MQTT)
	return true;
#else
	return false;
#endif
}

static inline bool config_have_xdp_tx_time(void)
{
#ifdef HAVE_XDP_TX_TIME
	return true;
#else
	return false;
#endif
}

static inline bool config_have_rx_timestamp(void)
{
#ifdef RX_TIMESTAMP
	return true;
#else
	return false;
#endif
}

static inline bool config_have_tx_timestamp(void)
{
#ifdef TX_TIMESTAMP
	return true;
#else
	return false;
#endif
}

#endif /* _CONFIG_H_ */
