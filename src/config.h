/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2020-2025 Linutronix GmbH
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
	bool log_via_mqtt;
	int log_via_mqtt_thread_priority;
	int log_via_mqtt_thread_cpu;
	size_t log_via_mqtt_broker_ip_length;
	char *log_via_mqtt_broker_ip;
	int log_via_mqtt_broker_port;
	int log_via_mqtt_keep_alive_secs;
	size_t log_via_mqtt_measurement_name_length;
	char *log_via_mqtt_measurement_name;
};

extern struct application_config app_config;

int config_read_from_file(const char *config_file);
int config_set_defaults(bool mirror_enabled);
void config_print_values(void);
bool config_sanity_check(void);
void config_free(void);

#define CONFIG_STORE_BOOL_PARAM_CLASS(name, var)                                                   \
	do {                                                                                       \
		if (!strcmp(key, #name)) {                                                         \
			enum stat_frame_type type = config_opt_to_type(#name);                     \
			bool result;                                                               \
                                                                                                   \
			if (config_parse_bool(value, &result)) {                                   \
				ret = -EINVAL;                                                     \
				fprintf(stderr, "The value for " #name " is invalid!\n");          \
				goto err_parse;                                                    \
			} else {                                                                   \
				app_config.classes[type].var = result;                             \
			}                                                                          \
		}                                                                                  \
	} while (0)

#define CONFIG_STORE_BOOL_PARAM(name, var)                                                         \
	do {                                                                                       \
		if (!strcmp(key, #name)) {                                                         \
			bool result;                                                               \
                                                                                                   \
			if (config_parse_bool(value, &result)) {                                   \
				ret = -EINVAL;                                                     \
				fprintf(stderr, "The value for " #name " is invalid!\n");          \
				goto err_parse;                                                    \
			} else {                                                                   \
				app_config.var = result;                                           \
			}                                                                          \
		}                                                                                  \
	} while (0)

#define CONFIG_STORE_INT_PARAM_CLASS(name, var)                                                    \
	do {                                                                                       \
		if (!strcmp(key, #name)) {                                                         \
			enum stat_frame_type type = config_opt_to_type(#name);                     \
			long result;                                                               \
                                                                                                   \
			if (config_parse_int(value, &result)) {                                    \
				ret = -ERANGE;                                                     \
				fprintf(stderr, "The value for " #name " is invalid!\n");          \
				goto err_parse;                                                    \
			} else {                                                                   \
				app_config.classes[type].var = result;                             \
			}                                                                          \
		}                                                                                  \
	} while (0)

#define CONFIG_STORE_INT_PARAM(name, var)                                                          \
	do {                                                                                       \
		if (!strcmp(key, #name)) {                                                         \
			long result;                                                               \
                                                                                                   \
			if (config_parse_int(value, &result)) {                                    \
				ret = -ERANGE;                                                     \
				fprintf(stderr, "The value for " #name " is invalid!\n");          \
				goto err_parse;                                                    \
			} else {                                                                   \
				app_config.var = result;                                           \
			}                                                                          \
		}                                                                                  \
	} while (0)

#define CONFIG_STORE_ULONG_PARAM_CLASS(name, var)                                                  \
	do {                                                                                       \
		if (!strcmp(key, #name)) {                                                         \
			enum stat_frame_type type = config_opt_to_type(#name);                     \
			unsigned long long result;                                                 \
                                                                                                   \
			if (config_parse_ulong(value, &result)) {                                  \
				ret = -ERANGE;                                                     \
				fprintf(stderr, "The value for " #name " is invalid!\n");          \
				goto err_parse;                                                    \
			} else {                                                                   \
				app_config.classes[type].var = result;                             \
			}                                                                          \
		}                                                                                  \
	} while (0)

#define CONFIG_STORE_TIME_PARAM_CLASS(name, var)                                                   \
	do {                                                                                       \
		if (!strcmp(key, #name)) {                                                         \
			enum stat_frame_type type = config_opt_to_type(#name);                     \
                                                                                                   \
			if (config_parse_time(value, &app_config.classes[type].var)) {             \
				ret = -ERANGE;                                                     \
				fprintf(stderr, "The value for " #name " is invalid!\n");          \
				goto err_parse;                                                    \
			}                                                                          \
		}                                                                                  \
	} while (0)

#define CONFIG_STORE_TIME_PARAM(name, var)                                                         \
	do {                                                                                       \
		if (!strcmp(key, #name)) {                                                         \
			if (config_parse_time(value, &app_config.var)) {                           \
				ret = -ERANGE;                                                     \
				fprintf(stderr, "The value for " #name " is invalid!\n");          \
				goto err_parse;                                                    \
			}                                                                          \
		}                                                                                  \
	} while (0)

#define CONFIG_STORE_STRING_PARAM_CLASS(name, var)                                                 \
	do {                                                                                       \
		if (!strcmp(key, #name)) {                                                         \
			enum stat_frame_type type = config_opt_to_type(#name);                     \
                                                                                                   \
			/* config_set_defaults() may have set a default value. */                  \
			free(app_config.classes[type].var);                                        \
			app_config.classes[type].var = strdup(value);                              \
			if (!app_config.classes[type].var) {                                       \
				ret = -ENOMEM;                                                     \
				fprintf(stderr, "strdup() for " #name " failed!\n");               \
				goto err_parse;                                                    \
			}                                                                          \
			app_config.classes[type].var##_length = strlen(value);                     \
		}                                                                                  \
	} while (0)

#define CONFIG_STORE_STRING_PARAM(name, var)                                                       \
	do {                                                                                       \
		if (!strcmp(key, #name)) {                                                         \
			/* config_set_defaults() may have set a default value. */                  \
			free(app_config.var);                                                      \
			app_config.var = strdup(value);                                            \
			if (!app_config.var) {                                                     \
				ret = -ENOMEM;                                                     \
				fprintf(stderr, "strdup() for " #name " failed!\n");               \
				goto err_parse;                                                    \
			}                                                                          \
			app_config.var##_length = strlen(value);                                   \
		}                                                                                  \
	} while (0)

#define CONFIG_STORE_INTERFACE_PARAM_CLASS(name, var)                                              \
	do {                                                                                       \
		if (!strcmp(key, #name)) {                                                         \
			enum stat_frame_type type = config_opt_to_type(#name);                     \
                                                                                                   \
			strncpy(app_config.classes[type].var, value,                               \
				sizeof(app_config.classes[type].var) - 1);                         \
		}                                                                                  \
	} while (0)

#define CONFIG_STORE_MAC_PARAM_CLASS(name, var)                                                    \
	do {                                                                                       \
		if (!strcmp(key, #name)) {                                                         \
			enum stat_frame_type type = config_opt_to_type(#name);                     \
			unsigned int tmp[ETH_ALEN];                                                \
			int i;                                                                     \
                                                                                                   \
			ret = sscanf(value, "%x:%x:%x:%x:%x:%x", &tmp[0], &tmp[1], &tmp[2],        \
				     &tmp[3], &tmp[4], &tmp[5]);                                   \
                                                                                                   \
			if (ret != ETH_ALEN) {                                                     \
				fprintf(stderr, "Failed to parse MAC Address!\n");                 \
				ret = -EINVAL;                                                     \
				goto err_parse;                                                    \
			}                                                                          \
                                                                                                   \
			for (i = 0; i < ETH_ALEN; ++i)                                             \
				app_config.classes[type].var[i] = (unsigned char)tmp[i];           \
		}                                                                                  \
	} while (0)

#define CONFIG_STORE_MAC_PARAM(name, var)                                                          \
	do {                                                                                       \
		if (!strcmp(key, #name)) {                                                         \
			unsigned int tmp[ETH_ALEN];                                                \
			int i;                                                                     \
                                                                                                   \
			ret = sscanf(value, "%x:%x:%x:%x:%x:%x", &tmp[0], &tmp[1], &tmp[2],        \
				     &tmp[3], &tmp[4], &tmp[5]);                                   \
                                                                                                   \
			if (ret != ETH_ALEN) {                                                     \
				fprintf(stderr, "Failed to parse MAC Address!\n");                 \
				ret = -EINVAL;                                                     \
				goto err_parse;                                                    \
			}                                                                          \
                                                                                                   \
			for (i = 0; i < ETH_ALEN; ++i)                                             \
				app_config.var[i] = (unsigned char)tmp[i];                         \
		}                                                                                  \
	} while (0)

#define CONFIG_STORE_CLOCKID_PARAM(name, var)                                                      \
	do {                                                                                       \
		if (!strcmp(key, #name)) {                                                         \
			if (strcmp(value, "CLOCK_TAI") && strcmp(value, "CLOCK_MONOTONIC")) {      \
				fprintf(stderr, "Invalid clockid specified!\n");                   \
				goto err_parse;                                                    \
			}                                                                          \
                                                                                                   \
			if (!strcmp(value, "CLOCK_TAI"))                                           \
				app_config.var = CLOCK_TAI;                                        \
			if (!strcmp(value, "CLOCK_MONOTONIC"))                                     \
				app_config.var = CLOCK_MONOTONIC;                                  \
		}                                                                                  \
	} while (0)

#define CONFIG_STORE_ETHER_TYPE_CLASS(name, var)                                                   \
	do {                                                                                       \
		if (!strcmp(key, #name)) {                                                         \
			enum stat_frame_type type = config_opt_to_type(#name);                     \
                                                                                                   \
			app_config.classes[type].var = strtoul(value, &endptr, 16);                \
			if (errno != 0 || endptr == value || *endptr != '\0') {                    \
				ret = -ERANGE;                                                     \
				fprintf(stderr, "The value for " #name " is invalid!\n");          \
				goto err_parse;                                                    \
			}                                                                          \
		}                                                                                  \
	} while (0)

#define CONFIG_STORE_SECURITY_MODE_PARAM_CLASS(name, var)                                          \
	do {                                                                                       \
		if (!strcmp(key, #name)) {                                                         \
			enum stat_frame_type type = config_opt_to_type(#name);                     \
                                                                                                   \
			if (strcasecmp(value, "none") && strcasecmp(value, "ao") &&                \
			    strcasecmp(value, "ae")) {                                             \
				fprintf(stderr, "Invalid security mode specified!\n");             \
				goto err_parse;                                                    \
			}                                                                          \
                                                                                                   \
			if (!strcasecmp(value, "none"))                                            \
				app_config.classes[type].var = SECURITY_MODE_NONE;                 \
			if (!strcasecmp(value, "ao"))                                              \
				app_config.classes[type].var = SECURITY_MODE_AO;                   \
			if (!strcasecmp(value, "ae"))                                              \
				app_config.classes[type].var = SECURITY_MODE_AE;                   \
		}                                                                                  \
	} while (0)

#define CONFIG_STORE_SECURITY_ALGORITHM_PARAM_CLASS(name, var)                                     \
	do {                                                                                       \
		if (!strcmp(key, #name)) {                                                         \
			enum stat_frame_type type = config_opt_to_type(#name);                     \
                                                                                                   \
			if (strcasecmp(value, "aes256-gcm") && strcasecmp(value, "aes128-gcm") &&  \
			    strcasecmp(value, "chacha20-poly1305")) {                              \
				fprintf(stderr, "Invalid security algorithm specified!\n");        \
				goto err_parse;                                                    \
			}                                                                          \
			if (!strcasecmp(value, "aes256-gcm"))                                      \
				app_config.classes[type].var = SECURITY_ALGORITHM_AES256_GCM;      \
			if (!strcasecmp(value, "aes128-gcm"))                                      \
				app_config.classes[type].var = SECURITY_ALGORITHM_AES128_GCM;      \
			if (!strcasecmp(value, "chacha20-poly1305"))                               \
				app_config.classes[type].var =                                     \
					SECURITY_ALGORITHM_CHACHA20_POLY1305;                      \
		}                                                                                  \
	} while (0)

bool config_is_traffic_class_active(const char *traffic_class);

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

#endif /* _CONFIG_H_ */
