// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2020-2026 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yaml.h>

#include <linux/if_ether.h>

#include "config.h"
#include "net_def.h"
#include "security.h"
#include "stat.h"
#include "utils.h"

#include "dcp_thread.h"
#include "layer2_thread.h"
#include "lldp_thread.h"
#include "rta_thread.h"
#include "rtc_thread.h"
#include "tsn_thread.h"
#include "udp_thread.h"

struct application_config app_config;

static bool str_match_second(const char *opt, const char *s)
{
	return !strncmp(opt, s, strlen(s));
}

static enum stat_frame_type config_opt_to_type(const char *opt)
{
	if (str_match_second(opt, "TsnHigh"))
		return TSN_HIGH_FRAME_TYPE;
	if (str_match_second(opt, "TsnLow"))
		return TSN_LOW_FRAME_TYPE;
	if (str_match_second(opt, "Rtc"))
		return RTC_FRAME_TYPE;
	if (str_match_second(opt, "Rta"))
		return RTA_FRAME_TYPE;
	if (str_match_second(opt, "Dcp"))
		return DCP_FRAME_TYPE;
	if (str_match_second(opt, "Lldp"))
		return LLDP_FRAME_TYPE;
	if (str_match_second(opt, "UdpHigh"))
		return UDP_HIGH_FRAME_TYPE;
	if (str_match_second(opt, "UdpLow"))
		return UDP_LOW_FRAME_TYPE;
	if (str_match_second(opt, "GenericL2"))
		return GENERICL2_FRAME_TYPE;

	/* Not a traffic class option */
	fprintf(stderr, "BUG: Invalid option '%s' found!\n", opt);
	return NUM_FRAME_TYPES;
}

bool config_is_traffic_class_active(const char *traffic_class)
{
	enum stat_frame_type type = config_opt_to_type(traffic_class);

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

	*ret = strtol(value, &endptr, 10);
	if (errno != 0 || endptr == value || *endptr != '\0')
		return -ERANGE;

	return 0;
}

static int config_parse_ulong(const char *value, unsigned long long *ret)
{
	char *endptr;

	*ret = strtoull(value, &endptr, 10);
	if (errno != 0 || endptr == value || *endptr != '\0')
		return -ERANGE;

	return 0;
}

static int config_parse_time(const char *value, uint64_t *ret)
{
	unsigned long long tmp;
	char *endptr;

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

/* The configuration file is YAML based. Use libyaml to parse it. */
int config_read_from_file(const char *config_file)
{
	bool base_time_seen = false;
	int ret, state_key = 0;
	yaml_parser_t parser;
	yaml_token_t token;
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
		char *endptr;

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
				/* Save key */
				key = strdup(value);
				if (!key) {
					fprintf(stderr, "No memory left!\n");
					goto err_parse;
				}

				continue;
			}

			if (!key)
				continue;

			/* Switch value */
			CONFIG_STORE_CLOCKID_PARAM(ApplicationClockId, application_clock_id);
			CONFIG_STORE_TIME_PARAM(ApplicationBaseCycleTimeNS,
						application_base_cycle_time_ns);
			CONFIG_STORE_TIME_PARAM(ApplicationBaseStartTimeNS,
						application_base_start_time_ns);
			CONFIG_STORE_TIME_PARAM(ApplicationBaseStartOffsetNS,
						application_base_start_offset_ns);
			CONFIG_STORE_TIME_PARAM(ApplicationTxBaseOffsetNS,
						application_tx_base_offset_ns);
			CONFIG_STORE_TIME_PARAM(ApplicationRxBaseOffsetNS,
						application_rx_base_offset_ns);
			CONFIG_STORE_STRING_PARAM(ApplicationXdpProgram, application_xdp_program);

			CONFIG_STORE_BOOL_PARAM_CLASS(TsnHighEnabled, enabled);
			CONFIG_STORE_BOOL_PARAM_CLASS(TsnHighXdpEnabled, xdp_enabled);
			CONFIG_STORE_BOOL_PARAM_CLASS(TsnHighXdpSkbMode, xdp_skb_mode);
			CONFIG_STORE_BOOL_PARAM_CLASS(TsnHighXdpZcMode, xdp_zc_mode);
			CONFIG_STORE_BOOL_PARAM_CLASS(TsnHighXdpWakeupMode, xdp_wakeup_mode);
			CONFIG_STORE_BOOL_PARAM_CLASS(TsnHighXdpBusyPollMode, xdp_busy_poll_mode);
			CONFIG_STORE_BOOL_PARAM_CLASS(TsnHighTxTimeEnabled, tx_time_enabled);
			CONFIG_STORE_BOOL_PARAM_CLASS(TsnHighIgnoreRxErrors, ignore_rx_errors);
			CONFIG_STORE_BOOL_PARAM_CLASS(TsnHighTxTimeStampEnabled,
						      tx_hwtstamp_enabled);
			CONFIG_STORE_TIME_PARAM_CLASS(TsnHighTxTimeOffsetNS, tx_time_offset_ns);
			CONFIG_STORE_INT_PARAM_CLASS(TsnHighVid, vid);
			CONFIG_STORE_INT_PARAM_CLASS(TsnHighPcp, pcp);
			CONFIG_STORE_ULONG_PARAM_CLASS(TsnHighNumFramesPerCycle,
						       num_frames_per_cycle);
			CONFIG_STORE_STRING_PARAM_CLASS(TsnHighPayloadPattern, payload_pattern);
			CONFIG_STORE_ULONG_PARAM_CLASS(TsnHighFrameLength, frame_length);
			CONFIG_STORE_SECURITY_MODE_PARAM_CLASS(TsnHighSecurityMode, security_mode);
			CONFIG_STORE_SECURITY_ALGORITHM_PARAM_CLASS(TsnHighSecurityAlgorithm,
								    security_algorithm);
			CONFIG_STORE_STRING_PARAM_CLASS(TsnHighSecurityKey, security_key);
			CONFIG_STORE_STRING_PARAM_CLASS(TsnHighSecurityIvPrefix,
							security_iv_prefix);
			CONFIG_STORE_INT_PARAM_CLASS(TsnHighRxQueue, rx_queue);
			CONFIG_STORE_INT_PARAM_CLASS(TsnHighTxQueue, tx_queue);
			CONFIG_STORE_INT_PARAM_CLASS(TsnHighSocketPriority, socket_priority);
			CONFIG_STORE_INT_PARAM_CLASS(TsnHighTxThreadPriority, tx_thread_priority);
			CONFIG_STORE_INT_PARAM_CLASS(TsnHighRxThreadPriority, rx_thread_priority);
			CONFIG_STORE_INT_PARAM_CLASS(TsnHighTxThreadCpu, tx_thread_cpu);
			CONFIG_STORE_INT_PARAM_CLASS(TsnHighRxThreadCpu, rx_thread_cpu);
			CONFIG_STORE_INTERFACE_PARAM_CLASS(TsnHighInterface, interface);
			CONFIG_STORE_MAC_PARAM_CLASS(TsnHighDestination, l2_destination);
			CONFIG_STORE_BOOL_PARAM_CLASS(TsnHighRxWorkloadEnabled,
						      rx_workload_enabled);
			CONFIG_STORE_BOOL_PARAM_CLASS(TsnHighRxWorkloadPrewarm,
						      rx_workload_prewarm);
			CONFIG_STORE_INT_PARAM_CLASS(TsnHighRxWorkloadSkipCount,
						     rx_workload_skip_count);
			CONFIG_STORE_STRING_PARAM_CLASS(TsnHighRxWorkloadFile, workload_file);
			CONFIG_STORE_STRING_PARAM_CLASS(TsnHighRxWorkloadSetupFunction,
							workload_setup_function);
			CONFIG_STORE_STRING_PARAM_CLASS(TsnHighRxWorkloadSetupArguments,
							workload_setup_arguments);
			CONFIG_STORE_STRING_PARAM_CLASS(TsnHighRxWorkloadFunction,
							workload_function);
			CONFIG_STORE_STRING_PARAM_CLASS(TsnHighRxWorkloadArguments,
							workload_arguments);
			CONFIG_STORE_INT_PARAM_CLASS(TsnHighRxWorkloadThreadCpu,
						     workload_thread_cpu);
			CONFIG_STORE_INT_PARAM_CLASS(TsnHighRxWorkloadThreadPriority,
						     workload_thread_priority);

			CONFIG_STORE_BOOL_PARAM_CLASS(TsnLowEnabled, enabled);
			CONFIG_STORE_BOOL_PARAM_CLASS(TsnLowXdpEnabled, xdp_enabled);
			CONFIG_STORE_BOOL_PARAM_CLASS(TsnLowXdpSkbMode, xdp_skb_mode);
			CONFIG_STORE_BOOL_PARAM_CLASS(TsnLowXdpZcMode, xdp_zc_mode);
			CONFIG_STORE_BOOL_PARAM_CLASS(TsnLowXdpWakeupMode, xdp_wakeup_mode);
			CONFIG_STORE_BOOL_PARAM_CLASS(TsnLowXdpBusyPollMode, xdp_busy_poll_mode);
			CONFIG_STORE_BOOL_PARAM_CLASS(TsnLowTxTimeEnabled, tx_time_enabled);
			CONFIG_STORE_BOOL_PARAM_CLASS(TsnLowIgnoreRxErrors, ignore_rx_errors);
			CONFIG_STORE_BOOL_PARAM_CLASS(TsnLowTxTimeStampEnabled,
						      tx_hwtstamp_enabled);
			CONFIG_STORE_TIME_PARAM_CLASS(TsnLowTxTimeOffsetNS, tx_time_offset_ns);
			CONFIG_STORE_INT_PARAM_CLASS(TsnLowVid, vid);
			CONFIG_STORE_INT_PARAM_CLASS(TsnLowPcp, pcp);
			CONFIG_STORE_ULONG_PARAM_CLASS(TsnLowNumFramesPerCycle,
						       num_frames_per_cycle);
			CONFIG_STORE_STRING_PARAM_CLASS(TsnLowPayloadPattern, payload_pattern);
			CONFIG_STORE_ULONG_PARAM_CLASS(TsnLowFrameLength, frame_length);
			CONFIG_STORE_SECURITY_MODE_PARAM_CLASS(TsnLowSecurityMode, security_mode);
			CONFIG_STORE_SECURITY_ALGORITHM_PARAM_CLASS(TsnLowSecurityAlgorithm,
								    security_algorithm);
			CONFIG_STORE_STRING_PARAM_CLASS(TsnLowSecurityKey, security_key);
			CONFIG_STORE_STRING_PARAM_CLASS(TsnLowSecurityIvPrefix, security_iv_prefix);
			CONFIG_STORE_INT_PARAM_CLASS(TsnLowRxQueue, rx_queue);
			CONFIG_STORE_INT_PARAM_CLASS(TsnLowTxQueue, tx_queue);
			CONFIG_STORE_INT_PARAM_CLASS(TsnLowSocketPriority, socket_priority);
			CONFIG_STORE_INT_PARAM_CLASS(TsnLowTxThreadPriority, tx_thread_priority);
			CONFIG_STORE_INT_PARAM_CLASS(TsnLowRxThreadPriority, rx_thread_priority);
			CONFIG_STORE_INT_PARAM_CLASS(TsnLowTxThreadCpu, tx_thread_cpu);
			CONFIG_STORE_INT_PARAM_CLASS(TsnLowRxThreadCpu, rx_thread_cpu);
			CONFIG_STORE_INTERFACE_PARAM_CLASS(TsnLowInterface, interface);
			CONFIG_STORE_MAC_PARAM_CLASS(TsnLowDestination, l2_destination);

			CONFIG_STORE_BOOL_PARAM_CLASS(RtcEnabled, enabled);
			CONFIG_STORE_BOOL_PARAM_CLASS(RtcXdpEnabled, xdp_enabled);
			CONFIG_STORE_BOOL_PARAM_CLASS(RtcXdpSkbMode, xdp_skb_mode);
			CONFIG_STORE_BOOL_PARAM_CLASS(RtcXdpZcMode, xdp_zc_mode);
			CONFIG_STORE_BOOL_PARAM_CLASS(RtcXdpWakeupMode, xdp_wakeup_mode);
			CONFIG_STORE_BOOL_PARAM_CLASS(RtcXdpBusyPollMode, xdp_busy_poll_mode);
			CONFIG_STORE_BOOL_PARAM_CLASS(RtcIgnoreRxErrors, ignore_rx_errors);
			CONFIG_STORE_BOOL_PARAM_CLASS(RtcTxTimeStampEnabled, tx_hwtstamp_enabled);
			CONFIG_STORE_INT_PARAM_CLASS(RtcVid, vid);
			CONFIG_STORE_INT_PARAM_CLASS(RtcPcp, pcp);
			CONFIG_STORE_ULONG_PARAM_CLASS(RtcNumFramesPerCycle, num_frames_per_cycle);
			CONFIG_STORE_STRING_PARAM_CLASS(RtcPayloadPattern, payload_pattern);
			CONFIG_STORE_ULONG_PARAM_CLASS(RtcFrameLength, frame_length);
			CONFIG_STORE_SECURITY_MODE_PARAM_CLASS(RtcSecurityMode, security_mode);
			CONFIG_STORE_SECURITY_ALGORITHM_PARAM_CLASS(RtcSecurityAlgorithm,
								    security_algorithm);
			CONFIG_STORE_STRING_PARAM_CLASS(RtcSecurityKey, security_key);
			CONFIG_STORE_STRING_PARAM_CLASS(RtcSecurityIvPrefix, security_iv_prefix);
			CONFIG_STORE_INT_PARAM_CLASS(RtcRxQueue, rx_queue);
			CONFIG_STORE_INT_PARAM_CLASS(RtcTxQueue, tx_queue);
			CONFIG_STORE_INT_PARAM_CLASS(RtcSocketPriority, socket_priority);
			CONFIG_STORE_INT_PARAM_CLASS(RtcTxThreadPriority, tx_thread_priority);
			CONFIG_STORE_INT_PARAM_CLASS(RtcRxThreadPriority, rx_thread_priority);
			CONFIG_STORE_INT_PARAM_CLASS(RtcTxThreadCpu, tx_thread_cpu);
			CONFIG_STORE_INT_PARAM_CLASS(RtcRxThreadCpu, rx_thread_cpu);
			CONFIG_STORE_INTERFACE_PARAM_CLASS(RtcInterface, interface);
			CONFIG_STORE_MAC_PARAM_CLASS(RtcDestination, l2_destination);
			CONFIG_STORE_BOOL_PARAM_CLASS(RtcRxWorkloadEnabled, rx_workload_enabled);
			CONFIG_STORE_BOOL_PARAM_CLASS(RtcRxWorkloadPrewarm, rx_workload_prewarm);
			CONFIG_STORE_INT_PARAM_CLASS(RtcRxWorkloadSkipCount,
						     rx_workload_skip_count);
			CONFIG_STORE_STRING_PARAM_CLASS(RtcRxWorkloadFile, workload_file);
			CONFIG_STORE_STRING_PARAM_CLASS(RtcRxWorkloadSetupFunction,
							workload_setup_function);
			CONFIG_STORE_STRING_PARAM_CLASS(RtcRxWorkloadSetupArguments,
							workload_setup_arguments);
			CONFIG_STORE_STRING_PARAM_CLASS(RtcRxWorkloadFunction, workload_function);
			CONFIG_STORE_STRING_PARAM_CLASS(RtcRxWorkloadArguments, workload_arguments);
			CONFIG_STORE_INT_PARAM_CLASS(RtcRxWorkloadThreadCpu, workload_thread_cpu);
			CONFIG_STORE_INT_PARAM_CLASS(RtcRxWorkloadThreadPriority,
						     workload_thread_priority);

			CONFIG_STORE_BOOL_PARAM_CLASS(RtaEnabled, enabled);
			CONFIG_STORE_BOOL_PARAM_CLASS(RtaXdpEnabled, xdp_enabled);
			CONFIG_STORE_BOOL_PARAM_CLASS(RtaXdpSkbMode, xdp_skb_mode);
			CONFIG_STORE_BOOL_PARAM_CLASS(RtaXdpZcMode, xdp_zc_mode);
			CONFIG_STORE_BOOL_PARAM_CLASS(RtaXdpWakeupMode, xdp_wakeup_mode);
			CONFIG_STORE_BOOL_PARAM_CLASS(RtaXdpBusyPollMode, xdp_busy_poll_mode);
			CONFIG_STORE_BOOL_PARAM_CLASS(RtaIgnoreRxErrors, ignore_rx_errors);
			CONFIG_STORE_BOOL_PARAM_CLASS(RtaTxTimeStampEnabled, tx_hwtstamp_enabled);
			CONFIG_STORE_INT_PARAM_CLASS(RtaVid, vid);
			CONFIG_STORE_INT_PARAM_CLASS(RtaPcp, pcp);
			CONFIG_STORE_TIME_PARAM_CLASS(RtaBurstPeriodNS, burst_period_ns);
			CONFIG_STORE_ULONG_PARAM_CLASS(RtaNumFramesPerCycle, num_frames_per_cycle);
			CONFIG_STORE_STRING_PARAM_CLASS(RtaPayloadPattern, payload_pattern);
			CONFIG_STORE_ULONG_PARAM_CLASS(RtaFrameLength, frame_length);
			CONFIG_STORE_SECURITY_MODE_PARAM_CLASS(RtaSecurityMode, security_mode);
			CONFIG_STORE_SECURITY_ALGORITHM_PARAM_CLASS(RtaSecurityAlgorithm,
								    security_algorithm);
			CONFIG_STORE_STRING_PARAM_CLASS(RtaSecurityKey, security_key);
			CONFIG_STORE_STRING_PARAM_CLASS(RtaSecurityIvPrefix, security_iv_prefix);
			CONFIG_STORE_INT_PARAM_CLASS(RtaRxQueue, rx_queue);
			CONFIG_STORE_INT_PARAM_CLASS(RtaTxQueue, tx_queue);
			CONFIG_STORE_INT_PARAM_CLASS(RtaSocketPriority, socket_priority);
			CONFIG_STORE_INT_PARAM_CLASS(RtaTxThreadPriority, tx_thread_priority);
			CONFIG_STORE_INT_PARAM_CLASS(RtaRxThreadPriority, rx_thread_priority);
			CONFIG_STORE_INT_PARAM_CLASS(RtaTxThreadCpu, tx_thread_cpu);
			CONFIG_STORE_INT_PARAM_CLASS(RtaRxThreadCpu, rx_thread_cpu);
			CONFIG_STORE_INTERFACE_PARAM_CLASS(RtaInterface, interface);
			CONFIG_STORE_MAC_PARAM_CLASS(RtaDestination, l2_destination);

			CONFIG_STORE_BOOL_PARAM_CLASS(DcpEnabled, enabled);
			CONFIG_STORE_BOOL_PARAM_CLASS(DcpIgnoreRxErrors, ignore_rx_errors);
			CONFIG_STORE_INT_PARAM_CLASS(DcpVid, vid);
			CONFIG_STORE_INT_PARAM_CLASS(DcpPcp, pcp);
			CONFIG_STORE_TIME_PARAM_CLASS(DcpBurstPeriodNS, burst_period_ns);
			CONFIG_STORE_ULONG_PARAM_CLASS(DcpNumFramesPerCycle, num_frames_per_cycle);
			CONFIG_STORE_STRING_PARAM_CLASS(DcpPayloadPattern, payload_pattern);
			CONFIG_STORE_ULONG_PARAM_CLASS(DcpFrameLength, frame_length);
			CONFIG_STORE_INT_PARAM_CLASS(DcpRxQueue, rx_queue);
			CONFIG_STORE_INT_PARAM_CLASS(DcpTxQueue, tx_queue);
			CONFIG_STORE_INT_PARAM_CLASS(DcpSocketPriority, socket_priority);
			CONFIG_STORE_INT_PARAM_CLASS(DcpTxThreadPriority, tx_thread_priority);
			CONFIG_STORE_INT_PARAM_CLASS(DcpRxThreadPriority, rx_thread_priority);
			CONFIG_STORE_INT_PARAM_CLASS(DcpTxThreadCpu, tx_thread_cpu);
			CONFIG_STORE_INT_PARAM_CLASS(DcpRxThreadCpu, rx_thread_cpu);
			CONFIG_STORE_INTERFACE_PARAM_CLASS(DcpInterface, interface);
			CONFIG_STORE_MAC_PARAM_CLASS(DcpDestination, l2_destination);

			CONFIG_STORE_BOOL_PARAM_CLASS(LldpEnabled, enabled);
			CONFIG_STORE_BOOL_PARAM_CLASS(LldpIgnoreRxErrors, ignore_rx_errors);
			CONFIG_STORE_TIME_PARAM_CLASS(LldpBurstPeriodNS, burst_period_ns);
			CONFIG_STORE_ULONG_PARAM_CLASS(LldpNumFramesPerCycle, num_frames_per_cycle);
			CONFIG_STORE_STRING_PARAM_CLASS(LldpPayloadPattern, payload_pattern);
			CONFIG_STORE_ULONG_PARAM_CLASS(LldpFrameLength, frame_length);
			CONFIG_STORE_INT_PARAM_CLASS(LldpRxQueue, rx_queue);
			CONFIG_STORE_INT_PARAM_CLASS(LldpTxQueue, tx_queue);
			CONFIG_STORE_INT_PARAM_CLASS(LldpSocketPriority, socket_priority);
			CONFIG_STORE_INT_PARAM_CLASS(LldpTxThreadPriority, tx_thread_priority);
			CONFIG_STORE_INT_PARAM_CLASS(LldpRxThreadPriority, rx_thread_priority);
			CONFIG_STORE_INT_PARAM_CLASS(LldpTxThreadCpu, tx_thread_cpu);
			CONFIG_STORE_INT_PARAM_CLASS(LldpRxThreadCpu, rx_thread_cpu);
			CONFIG_STORE_INTERFACE_PARAM_CLASS(LldpInterface, interface);
			CONFIG_STORE_MAC_PARAM_CLASS(LldpDestination, l2_destination);

			CONFIG_STORE_BOOL_PARAM_CLASS(UdpHighEnabled, enabled);
			CONFIG_STORE_BOOL_PARAM_CLASS(UdpHighIgnoreRxErrors, ignore_rx_errors);
			CONFIG_STORE_TIME_PARAM_CLASS(UdpHighBurstPeriodNS, burst_period_ns);
			CONFIG_STORE_ULONG_PARAM_CLASS(UdpHighNumFramesPerCycle,
						       num_frames_per_cycle);
			CONFIG_STORE_STRING_PARAM_CLASS(UdpHighPayloadPattern, payload_pattern);
			CONFIG_STORE_ULONG_PARAM_CLASS(UdpHighFrameLength, frame_length);
			CONFIG_STORE_INT_PARAM_CLASS(UdpHighRxQueue, rx_queue);
			CONFIG_STORE_INT_PARAM_CLASS(UdpHighTxQueue, tx_queue);
			CONFIG_STORE_INT_PARAM_CLASS(UdpHighSocketPriority, socket_priority);
			CONFIG_STORE_INT_PARAM_CLASS(UdpHighTxThreadPriority, tx_thread_priority);
			CONFIG_STORE_INT_PARAM_CLASS(UdpHighRxThreadPriority, rx_thread_priority);
			CONFIG_STORE_INT_PARAM_CLASS(UdpHighTxThreadCpu, tx_thread_cpu);
			CONFIG_STORE_INT_PARAM_CLASS(UdpHighRxThreadCpu, rx_thread_cpu);
			CONFIG_STORE_INTERFACE_PARAM_CLASS(UdpHighInterface, interface);
			CONFIG_STORE_STRING_PARAM_CLASS(UdpHighPort, l3_port);
			CONFIG_STORE_STRING_PARAM_CLASS(UdpHighDestination, l3_destination);
			CONFIG_STORE_STRING_PARAM_CLASS(UdpHighSource, l3_source);

			CONFIG_STORE_BOOL_PARAM_CLASS(UdpLowEnabled, enabled);
			CONFIG_STORE_BOOL_PARAM_CLASS(UdpLowIgnoreRxErrors, ignore_rx_errors);
			CONFIG_STORE_TIME_PARAM_CLASS(UdpLowBurstPeriodNS, burst_period_ns);
			CONFIG_STORE_ULONG_PARAM_CLASS(UdpLowNumFramesPerCycle,
						       num_frames_per_cycle);
			CONFIG_STORE_STRING_PARAM_CLASS(UdpLowPayloadPattern, payload_pattern);
			CONFIG_STORE_ULONG_PARAM_CLASS(UdpLowFrameLength, frame_length);
			CONFIG_STORE_INT_PARAM_CLASS(UdpLowRxQueue, rx_queue);
			CONFIG_STORE_INT_PARAM_CLASS(UdpLowTxQueue, tx_queue);
			CONFIG_STORE_INT_PARAM_CLASS(UdpLowSocketPriority, socket_priority);
			CONFIG_STORE_INT_PARAM_CLASS(UdpLowTxThreadPriority, tx_thread_priority);
			CONFIG_STORE_INT_PARAM_CLASS(UdpLowRxThreadPriority, rx_thread_priority);
			CONFIG_STORE_INT_PARAM_CLASS(UdpLowTxThreadCpu, tx_thread_cpu);
			CONFIG_STORE_INT_PARAM_CLASS(UdpLowRxThreadCpu, rx_thread_cpu);
			CONFIG_STORE_INTERFACE_PARAM_CLASS(UdpLowInterface, interface);
			CONFIG_STORE_STRING_PARAM_CLASS(UdpLowPort, l3_port);
			CONFIG_STORE_STRING_PARAM_CLASS(UdpLowDestination, l3_destination);
			CONFIG_STORE_STRING_PARAM_CLASS(UdpLowSource, l3_source);

			CONFIG_STORE_STRING_PARAM_CLASS(GenericL2Name, name);
			CONFIG_STORE_BOOL_PARAM_CLASS(GenericL2Enabled, enabled);
			CONFIG_STORE_BOOL_PARAM_CLASS(GenericL2XdpEnabled, xdp_enabled);
			CONFIG_STORE_BOOL_PARAM_CLASS(GenericL2XdpSkbMode, xdp_skb_mode);
			CONFIG_STORE_BOOL_PARAM_CLASS(GenericL2XdpZcMode, xdp_zc_mode);
			CONFIG_STORE_BOOL_PARAM_CLASS(GenericL2XdpWakeupMode, xdp_wakeup_mode);
			CONFIG_STORE_BOOL_PARAM_CLASS(GenericL2XdpBusyPollMode, xdp_busy_poll_mode);
			CONFIG_STORE_BOOL_PARAM_CLASS(GenericL2TxTimeEnabled, tx_time_enabled);
			CONFIG_STORE_BOOL_PARAM_CLASS(GenericL2IgnoreRxErrors, ignore_rx_errors);
			CONFIG_STORE_BOOL_PARAM_CLASS(GenericL2TxTimeStampEnabled,
						      tx_hwtstamp_enabled);
			CONFIG_STORE_TIME_PARAM_CLASS(GenericL2TxTimeOffsetNS, tx_time_offset_ns);
			CONFIG_STORE_INT_PARAM_CLASS(GenericL2Vid, vid);
			CONFIG_STORE_INT_PARAM_CLASS(GenericL2Pcp, pcp);
			CONFIG_STORE_ETHER_TYPE_CLASS(GenericL2EtherType, ether_type);
			CONFIG_STORE_ULONG_PARAM_CLASS(GenericL2NumFramesPerCycle,
						       num_frames_per_cycle);
			CONFIG_STORE_STRING_PARAM_CLASS(GenericL2PayloadPattern, payload_pattern);
			CONFIG_STORE_ULONG_PARAM_CLASS(GenericL2FrameLength, frame_length);
			CONFIG_STORE_INT_PARAM_CLASS(GenericL2RxQueue, rx_queue);
			CONFIG_STORE_INT_PARAM_CLASS(GenericL2TxQueue, tx_queue);
			CONFIG_STORE_INT_PARAM_CLASS(GenericL2SocketPriority, socket_priority);
			CONFIG_STORE_INT_PARAM_CLASS(GenericL2TxThreadPriority, tx_thread_priority);
			CONFIG_STORE_INT_PARAM_CLASS(GenericL2RxThreadPriority, rx_thread_priority);
			CONFIG_STORE_INT_PARAM_CLASS(GenericL2TxThreadCpu, tx_thread_cpu);
			CONFIG_STORE_INT_PARAM_CLASS(GenericL2RxThreadCpu, rx_thread_cpu);
			CONFIG_STORE_INTERFACE_PARAM_CLASS(GenericL2Interface, interface);
			CONFIG_STORE_MAC_PARAM_CLASS(GenericL2Destination, l2_destination);
			CONFIG_STORE_BOOL_PARAM_CLASS(GenericL2RxWorkloadEnabled,
						      rx_workload_enabled);
			CONFIG_STORE_BOOL_PARAM_CLASS(GenericL2RxWorkloadPrewarm,
						      rx_workload_prewarm);
			CONFIG_STORE_INT_PARAM_CLASS(GenericL2RxWorkloadSkipCount,
						     rx_workload_skip_count);
			CONFIG_STORE_STRING_PARAM_CLASS(GenericL2RxWorkloadFile, workload_file);
			CONFIG_STORE_STRING_PARAM_CLASS(GenericL2RxWorkloadSetupFunction,
							workload_setup_function);
			CONFIG_STORE_STRING_PARAM_CLASS(GenericL2RxWorkloadSetupArguments,
							workload_setup_arguments);
			CONFIG_STORE_STRING_PARAM_CLASS(GenericL2RxWorkloadFunction,
							workload_function);
			CONFIG_STORE_STRING_PARAM_CLASS(GenericL2RxWorkloadArguments,
							workload_arguments);
			CONFIG_STORE_INT_PARAM_CLASS(GenericL2RxWorkloadThreadCpu,
						     workload_thread_cpu);
			CONFIG_STORE_INT_PARAM_CLASS(GenericL2RxWorkloadThreadPriority,
						     workload_thread_priority);

			CONFIG_STORE_INT_PARAM(LogThreadPriority, log_thread_priority);
			CONFIG_STORE_INT_PARAM(LogThreadCpu, log_thread_cpu);
			CONFIG_STORE_STRING_PARAM(LogFile, log_file);
			CONFIG_STORE_STRING_PARAM(LogLevel, log_level);

			CONFIG_STORE_BOOL_PARAM(DebugStopTraceOnOutlier,
						debug_stop_trace_on_outlier);
			CONFIG_STORE_BOOL_PARAM(DebugStopTraceOnError, debug_stop_trace_on_error);
			CONFIG_STORE_BOOL_PARAM(DebugMonitorMode, debug_monitor_mode);
			CONFIG_STORE_MAC_PARAM(DebugMonitorDestination, debug_monitor_destination);

			CONFIG_STORE_BOOL_PARAM(StatsHistogramEnabled, stats_histogram_enabled);
			CONFIG_STORE_TIME_PARAM(StatsHistogramMinimumNS,
						stats_histogram_minimum_ns);
			CONFIG_STORE_TIME_PARAM(StatsHistogramMaximumNS,
						stats_histogram_maximum_ns);
			CONFIG_STORE_STRING_PARAM(StatsHistogramFile, stats_histogram_file);
			CONFIG_STORE_TIME_PARAM(StatsCollectionIntervalNS,
						stats_collection_interval_ns);

			CONFIG_STORE_BOOL_PARAM(LogMqtt, log_mqtt);
			CONFIG_STORE_INT_PARAM(LogMqttThreadPriority, log_mqtt_thread_priority);
			CONFIG_STORE_INT_PARAM(LogMqttThreadCpu, log_mqtt_thread_cpu);
			CONFIG_STORE_STRING_PARAM(LogMqttBrokerIP, log_mqtt_broker_ip);
			CONFIG_STORE_INT_PARAM(LogMqttBrokerPort, log_mqtt_broker_port);
			CONFIG_STORE_INT_PARAM(LogMqttKeepAliveSecs, log_mqtt_keep_alive_secs);
			CONFIG_STORE_STRING_PARAM(LogMqttMeasurementName,
						  log_mqtt_measurement_name);

			CONFIG_STORE_BOOL_PARAM(LogJson, log_json);
			CONFIG_STORE_INT_PARAM(LogJsonThreadPriority, log_json_thread_priority);
			CONFIG_STORE_INT_PARAM(LogJsonThreadCpu, log_json_thread_cpu);
			CONFIG_STORE_STRING_PARAM(LogJsonHost, log_json_host);
			CONFIG_STORE_STRING_PARAM(LogJsonPort, log_json_port);
			CONFIG_STORE_STRING_PARAM(LogJsonMeasurementName,
						  log_json_measurement_name);

			if (!strcmp(key, "ApplicationBaseStartTimeNS"))
				base_time_seen = true;

			if (key)
				free(key);

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

		clock_gettime(app_config.application_clock_id, &current);
		app_config.application_base_start_time_ns = (current.tv_sec + 30) * NSEC_PER_SEC;
	}

	ret = 0;

err_parse:
	yaml_token_delete(&token);
	yaml_parser_delete(&parser);

err_yaml:
	fclose(f);

	return ret;
}

void config_print_values(void)
{
	const struct traffic_class_config *conf;

	printf("--------------------------------------------------------------------------------"
	       "\n");
	printf("ApplicationClockId=%s\n",
	       app_config.application_clock_id == CLOCK_TAI ? "CLOCK_TAI" : "CLOCK_MONOTONIC");
	printf("ApplicationBaseCycleTimeNS=%" PRIu64 "\n",
	       app_config.application_base_cycle_time_ns);
	printf("ApplicationBaseStartTimeNS=%" PRIu64 "\n",
	       app_config.application_base_start_time_ns);
	printf("ApplicationBaseStartOffsetNS=%" PRIu64 "\n",
	       app_config.application_base_start_offset_ns);
	printf("ApplicationTxBaseOffsetNS=%" PRIu64 "\n", app_config.application_tx_base_offset_ns);
	printf("ApplicationRxBaseOffsetNS=%" PRIu64 "\n", app_config.application_rx_base_offset_ns);
	printf("ApplicationXdpProgram=%s\n", app_config.application_xdp_program);
	printf("--------------------------------------------------------------------------------"
	       "\n");

	conf = &app_config.classes[TSN_HIGH_FRAME_TYPE];
	if (config_is_traffic_class_active("TsnHigh")) {
		printf("TsnHighEnabled=%s\n", conf->enabled ? "True" : "False");
		printf("TsnHighRxMirrorEnabled=%s\n", conf->rx_mirror_enabled ? "True" : "False");
		printf("TsnHighXdpEnabled=%s\n", conf->xdp_enabled ? "True" : "False");
		printf("TsnHighXdpSkbMode=%s\n", conf->xdp_skb_mode ? "True" : "False");
		printf("TsnHighXdpZcMode=%s\n", conf->xdp_zc_mode ? "True" : "False");
		printf("TsnHighXdpWakeupMode=%s\n", conf->xdp_wakeup_mode ? "True" : "False");
		printf("TsnHighXdpBusyPollMode=%s\n", conf->xdp_busy_poll_mode ? "True" : "False");
		printf("TsnHighTxTimeEnabled=%s\n", conf->tx_time_enabled ? "True" : "False");
		printf("TsnHighIgnoreRxErrors=%s\n", conf->ignore_rx_errors ? "True" : "False");
		printf("TsnHighTxTimeOffsetNS=%" PRIu64 "\n", conf->tx_time_offset_ns);
		printf("TsnHighTxTimeStampEnabled=%s\n",
		       conf->tx_hwtstamp_enabled ? "True" : "False");
		printf("TsnHighVid=%d\n", conf->vid);
		printf("TsnHighPcp=%d\n", conf->pcp);
		printf("TsnHighNumFramesPerCycle=%zu\n", conf->num_frames_per_cycle);
		printf("TsnHighPayloadPattern=");
		print_payload_pattern(conf->payload_pattern, conf->payload_pattern_length);
		printf("\n");
		printf("TsnHighFrameLength=%zu\n", conf->frame_length);
		printf("TsnHighSecurityMode=%s\n", security_mode_to_string(conf->security_mode));
		printf("TsnHighSecurityAlgorithm=%s\n",
		       security_algorithm_to_string(conf->security_algorithm));
		printf("TsnHighSecurityKey=%s\n", conf->security_key);
		printf("TsnHighSecurityIvPrefix=%s\n", conf->security_iv_prefix);
		printf("TsnHighRxQueue=%d\n", conf->rx_queue);
		printf("TsnHighTxQueue=%d\n", conf->tx_queue);
		printf("TsnHighSocketPriority=%d\n", conf->socket_priority);
		printf("TsnHighTxThreadPriority=%d\n", conf->tx_thread_priority);
		printf("TsnHighRxThreadPriority=%d\n", conf->rx_thread_priority);
		printf("TsnHighTxThreadCpu=%d\n", conf->tx_thread_cpu);
		printf("TsnHighRxThreadCpu=%d\n", conf->rx_thread_cpu);
		printf("TsnHighInterface=%s\n", conf->interface);
		printf("TsnHighDestination=");
		print_mac_address(conf->l2_destination);
		printf("\n");
		printf("TsnHighRxWorkloadEnabled=%s\n",
		       conf->rx_workload_enabled ? "True" : "False");
		printf("TsnHighRxWorkloadPrewarm=%s\n",
		       conf->rx_workload_prewarm ? "True" : "False");
		printf("TsnHighRxWorkloadSkipCount=%d\n", conf->rx_workload_skip_count);
		printf("TsnHighRxWorkloadFile=%s\n", conf->workload_file);
		printf("TsnHighRxWorkloadSetupFunction=%s\n", conf->workload_setup_function);
		printf("TsnHighRxWorkloadSetupArguments=%s\n", conf->workload_setup_arguments);
		printf("TsnHighRxWorkloadFunction=%s\n", conf->workload_function);
		printf("TsnHighRxWorkloadArguments=%s\n", conf->workload_arguments);
		printf("TsnHighRxWorkloadThreadCpu=%d\n", conf->workload_thread_cpu);
		printf("TsnHighRxWorkloadThreadPriority=%d\n", conf->workload_thread_priority);
		printf("---------------------------------------------------------------------------"
		       "-----\n");
	}

	conf = &app_config.classes[TSN_LOW_FRAME_TYPE];
	if (config_is_traffic_class_active("TsnLow")) {
		printf("TsnLowEnabled=%s\n", conf->enabled ? "True" : "False");
		printf("TsnLowRxMirrorEnabled=%s\n", conf->rx_mirror_enabled ? "True" : "False");
		printf("TsnLowXdpEnabled=%s\n", conf->xdp_enabled ? "True" : "False");
		printf("TsnLowXdpSkbMode=%s\n", conf->xdp_skb_mode ? "True" : "False");
		printf("TsnLowXdpZcMode=%s\n", conf->xdp_zc_mode ? "True" : "False");
		printf("TsnLowXdpWakeupMode=%s\n", conf->xdp_wakeup_mode ? "True" : "False");
		printf("TsnLowXdpBusyPollMode=%s\n", conf->xdp_busy_poll_mode ? "True" : "False");
		printf("TsnLowTxTimeEnabled=%s\n", conf->tx_time_enabled ? "True" : "False");
		printf("TsnLowIgnoreRxErrors=%s\n", conf->ignore_rx_errors ? "True" : "False");
		printf("TsnLowTxTimeOffsetNS=%" PRIu64 "\n", conf->tx_time_offset_ns);
		printf("TsnLowTxTimeStampEnabled=%s\n",
		       conf->tx_hwtstamp_enabled ? "True" : "False");
		printf("TsnLowVid=%d\n", conf->vid);
		printf("TsnLowPcp=%d\n", conf->pcp);
		printf("TsnLowNumFramesPerCycle=%zu\n", conf->num_frames_per_cycle);
		printf("TsnLowPayloadPattern=");
		print_payload_pattern(conf->payload_pattern, conf->payload_pattern_length);
		printf("\n");
		printf("TsnLowFrameLength=%zu\n", conf->frame_length);
		printf("TsnLowSecurityMode=%s\n", security_mode_to_string(conf->security_mode));
		printf("TsnLowSecurityAlgorithm=%s\n",
		       security_algorithm_to_string(conf->security_algorithm));
		printf("TsnLowSecurityKey=%s\n", conf->security_key);
		printf("TsnLowSecurityIvPrefix=%s\n", conf->security_iv_prefix);
		printf("TsnLowRxQueue=%d\n", conf->rx_queue);
		printf("TsnLowTxQueue=%d\n", conf->tx_queue);
		printf("TsnLowSocketPriority=%d\n", conf->socket_priority);
		printf("TsnLowTxThreadPriority=%d\n", conf->tx_thread_priority);
		printf("TsnLowRxThreadPriority=%d\n", conf->rx_thread_priority);
		printf("TsnLowTxThreadCpu=%d\n", conf->tx_thread_cpu);
		printf("TsnLowRxThreadCpu=%d\n", conf->rx_thread_cpu);
		printf("TsnLowInterface=%s\n", conf->interface);
		printf("TsnLowDestination=");
		print_mac_address(conf->l2_destination);
		printf("\n");
		printf("---------------------------------------------------------------------------"
		       "-----\n");
	}

	conf = &app_config.classes[RTC_FRAME_TYPE];
	if (config_is_traffic_class_active("Rtc")) {
		printf("RtcEnabled=%s\n", conf->enabled ? "True" : "False");
		printf("RtcRxMirrorEnabled=%s\n", conf->rx_mirror_enabled ? "True" : "False");
		printf("RtcXdpEnabled=%s\n", conf->xdp_enabled ? "True" : "False");
		printf("RtcXdpSkbMode=%s\n", conf->xdp_skb_mode ? "True" : "False");
		printf("RtcXdpZcMode=%s\n", conf->xdp_zc_mode ? "True" : "False");
		printf("RtcXdpWakeupMode=%s\n", conf->xdp_wakeup_mode ? "True" : "False");
		printf("RtcXdpBusyPollMode=%s\n", conf->xdp_busy_poll_mode ? "True" : "False");
		printf("RtcIgnoreRxErrors=%s\n", conf->ignore_rx_errors ? "True" : "False");
		printf("RtcTxTimeStampEnabled=%s\n", conf->tx_hwtstamp_enabled ? "True" : "False");
		printf("RtcVid=%d\n", conf->vid);
		printf("RtcPcp=%d\n", conf->pcp);
		printf("RtcNumFramesPerCycle=%zu\n", conf->num_frames_per_cycle);
		printf("RtcPayloadPattern=");
		print_payload_pattern(conf->payload_pattern, conf->payload_pattern_length);
		printf("\n");
		printf("RtcFrameLength=%zu\n", conf->frame_length);
		printf("RtcSecurityMode=%s\n", security_mode_to_string(conf->security_mode));
		printf("RtcSecurityAlgorithm=%s\n",
		       security_algorithm_to_string(conf->security_algorithm));
		printf("RtcSecurityKey=%s\n", conf->security_key);
		printf("RtcSecurityIvPrefix=%s\n", conf->security_iv_prefix);
		printf("RtcRxQueue=%d\n", conf->rx_queue);
		printf("RtcTxQueue=%d\n", conf->tx_queue);
		printf("RtcSocketPriority=%d\n", conf->socket_priority);
		printf("RtcTxThreadPriority=%d\n", conf->tx_thread_priority);
		printf("RtcRxThreadPriority=%d\n", conf->rx_thread_priority);
		printf("RtcTxThreadCpu=%d\n", conf->tx_thread_cpu);
		printf("RtcRxThreadCpu=%d\n", conf->rx_thread_cpu);
		printf("RtcInterface=%s\n", conf->interface);
		printf("RtcDestination=");
		print_mac_address(conf->l2_destination);
		printf("RtcRxWorkloadEnabled=%s\n", conf->rx_workload_enabled ? "True" : "False");
		printf("RtcRxWorkloadPrewarm=%s\n", conf->rx_workload_prewarm ? "True" : "False");
		printf("RtcRxWorkloadSkipCount=%d\n", conf->rx_workload_skip_count);
		printf("RtcRxWorkloadFile=%s\n", conf->workload_file);
		printf("RtcRxWorkloadSetupFunction=%s\n", conf->workload_setup_function);
		printf("RtcRxWorkloadSetupArguments=%s\n", conf->workload_setup_arguments);
		printf("RtcRxWorkloadFunction=%s\n", conf->workload_function);
		printf("RtcRxWorkloadArguments=%s\n", conf->workload_arguments);
		printf("RtcRxWorkloadThreadCpu=%d\n", conf->workload_thread_cpu);
		printf("RtcRxWorkloadThreadPriority=%d\n", conf->workload_thread_priority);
		printf("\n");
		printf("---------------------------------------------------------------------------"
		       "-----\n");
	}

	conf = &app_config.classes[RTA_FRAME_TYPE];
	if (config_is_traffic_class_active("Rta")) {
		printf("RtaEnabled=%s\n", conf->enabled ? "True" : "False");
		printf("RtaRxMirrorEnabled=%s\n", conf->rx_mirror_enabled ? "True" : "False");
		printf("RtaXdpEnabled=%s\n", conf->xdp_enabled ? "True" : "False");
		printf("RtaXdpSkbMode=%s\n", conf->xdp_skb_mode ? "True" : "False");
		printf("RtaXdpZcMode=%s\n", conf->xdp_zc_mode ? "True" : "False");
		printf("RtaXdpWakeupMode=%s\n", conf->xdp_wakeup_mode ? "True" : "False");
		printf("RtaXdpBusyPollMode=%s\n", conf->xdp_busy_poll_mode ? "True" : "False");
		printf("RtaIgnoreRxErrors=%s\n", conf->ignore_rx_errors ? "True" : "False");
		printf("RtaTxTimeStampEnabled=%s\n", conf->tx_hwtstamp_enabled ? "True" : "False");
		printf("RtaVid=%d\n", conf->vid);
		printf("RtaPcp=%d\n", conf->pcp);
		printf("RtaBurstPeriodNS=%" PRIu64 "\n", conf->burst_period_ns);
		printf("RtaNumFramesPerCycle=%zu\n", conf->num_frames_per_cycle);
		printf("RtaPayloadPattern=");
		print_payload_pattern(conf->payload_pattern, conf->payload_pattern_length);
		printf("\n");
		printf("RtaFrameLength=%zu\n", conf->frame_length);
		printf("RtaSecurityMode=%s\n", security_mode_to_string(conf->security_mode));
		printf("RtaSecurityAlgorithm=%s\n",
		       security_algorithm_to_string(conf->security_algorithm));
		printf("RtaSecurityKey=%s\n", conf->security_key);
		printf("RtaSecurityIvPrefix=%s\n", conf->security_iv_prefix);
		printf("RtaRxQueue=%d\n", conf->rx_queue);
		printf("RtaTxQueue=%d\n", conf->tx_queue);
		printf("RtaSocketPriority=%d\n", conf->socket_priority);
		printf("RtaTxThreadPriority=%d\n", conf->tx_thread_priority);
		printf("RtaRxThreadPriority=%d\n", conf->rx_thread_priority);
		printf("RtaTxThreadCpu=%d\n", conf->tx_thread_cpu);
		printf("RtaRxThreadCpu=%d\n", conf->rx_thread_cpu);
		printf("RtaInterface=%s\n", conf->interface);
		printf("RtaDestination=");
		print_mac_address(conf->l2_destination);
		printf("\n");
		printf("---------------------------------------------------------------------------"
		       "-----\n");
	}

	conf = &app_config.classes[DCP_FRAME_TYPE];
	if (config_is_traffic_class_active("Dcp")) {
		printf("DcpEnabled=%s\n", conf->enabled ? "True" : "False");
		printf("DcpRxMirrorEnabled=%s\n", conf->rx_mirror_enabled ? "True" : "False");
		printf("DcpIgnoreRxErrors=%s\n", conf->ignore_rx_errors ? "True" : "False");
		printf("DcpVid=%d\n", conf->vid);
		printf("DcpPcp=%d\n", conf->pcp);
		printf("DcpBurstPeriodNS=%" PRIu64 "\n", conf->burst_period_ns);
		printf("DcpNumFramesPerCycle=%zu\n", conf->num_frames_per_cycle);
		printf("DcpPayloadPattern=");
		print_payload_pattern(conf->payload_pattern, conf->payload_pattern_length);
		printf("\n");
		printf("DcpFrameLength=%zu\n", conf->frame_length);
		printf("DcpRxQueue=%d\n", conf->rx_queue);
		printf("DcpTxQueue=%d\n", conf->tx_queue);
		printf("DcpSocketPriority=%d\n", conf->socket_priority);
		printf("DcpTxThreadPriority=%d\n", conf->tx_thread_priority);
		printf("DcpRxThreadPriority=%d\n", conf->rx_thread_priority);
		printf("DcpTxThreadCpu=%d\n", conf->tx_thread_cpu);
		printf("DcpRxThreadCpu=%d\n", conf->rx_thread_cpu);
		printf("DcpInterface=%s\n", conf->interface);
		printf("DcpDestination=");
		print_mac_address(conf->l2_destination);
		printf("\n");
		printf("---------------------------------------------------------------------------"
		       "-----\n");
	}

	conf = &app_config.classes[LLDP_FRAME_TYPE];
	if (config_is_traffic_class_active("Lldp")) {
		printf("LldpEnabled=%s\n", conf->enabled ? "True" : "False");
		printf("LldpRxMirrorEnabled=%s\n", conf->rx_mirror_enabled ? "True" : "False");
		printf("LldpIgnoreRxErrors=%s\n", conf->ignore_rx_errors ? "True" : "False");
		printf("LldpBurstPeriodNS=%" PRIu64 "\n", conf->burst_period_ns);
		printf("LldpNumFramesPerCycle=%zu\n", conf->num_frames_per_cycle);
		printf("LldpPayloadPattern=");
		print_payload_pattern(conf->payload_pattern, conf->payload_pattern_length);
		printf("\n");
		printf("LldpFrameLength=%zu\n", conf->frame_length);
		printf("LldpRxQueue=%d\n", conf->rx_queue);
		printf("LldpTxQueue=%d\n", conf->tx_queue);
		printf("LldpSocketPriority=%d\n", conf->socket_priority);
		printf("LldpTxThreadPriority=%d\n", conf->tx_thread_priority);
		printf("LldpRxThreadPriority=%d\n", conf->rx_thread_priority);
		printf("LldpTxThreadCpu=%d\n", conf->tx_thread_cpu);
		printf("LldpRxThreadCpu=%d\n", conf->rx_thread_cpu);
		printf("LldpInterface=%s\n", conf->interface);
		printf("LldpDestination=");
		print_mac_address(conf->l2_destination);
		printf("\n");
		printf("---------------------------------------------------------------------------"
		       "-----\n");
	}

	conf = &app_config.classes[UDP_HIGH_FRAME_TYPE];
	if (config_is_traffic_class_active("UdpHigh")) {
		printf("UdpHighEnabled=%s\n", conf->enabled ? "True" : "False");
		printf("UdpHighRxMirrorEnabled=%s\n", conf->rx_mirror_enabled ? "True" : "False");
		printf("UdpHighIgnoreRxErrors=%s\n", conf->ignore_rx_errors ? "True" : "False");
		printf("UdpHighBurstPeriodNS=%" PRIu64 "\n", conf->burst_period_ns);
		printf("UdpHighNumFramesPerCycle=%zu\n", conf->num_frames_per_cycle);
		printf("UdpHighPayloadPattern=");
		print_payload_pattern(conf->payload_pattern, conf->payload_pattern_length);
		printf("\n");
		printf("UdpHighFrameLength=%zu\n", conf->frame_length);
		printf("UdpHighRxQueue=%d\n", conf->rx_queue);
		printf("UdpHighTxQueue=%d\n", conf->tx_queue);
		printf("UdpHighSocketPriority=%d\n", conf->socket_priority);
		printf("UdpHighTxThreadPriority=%d\n", conf->tx_thread_priority);
		printf("UdpHighRxThreadPriority=%d\n", conf->rx_thread_priority);
		printf("UdpHighTxThreadCpu=%d\n", conf->tx_thread_cpu);
		printf("UdpHighRxThreadCpu=%d\n", conf->rx_thread_cpu);
		printf("UdpHighInterface=%s\n", conf->interface);
		printf("UdpHighPort=%s\n", conf->l3_port);
		printf("UdpHighDestination=%s\n", conf->l3_destination);
		printf("UdpHighSource=%s\n", conf->l3_source);
		printf("---------------------------------------------------------------------------"
		       "-----\n");
	}

	conf = &app_config.classes[UDP_LOW_FRAME_TYPE];
	if (config_is_traffic_class_active("UdpLow")) {
		printf("UdpLowEnabled=%s\n", conf->enabled ? "True" : "False");
		printf("UdpLowRxMirrorEnabled=%s\n", conf->rx_mirror_enabled ? "True" : "False");
		printf("UdpLowIgnoreRxErrors=%s\n", conf->ignore_rx_errors ? "True" : "False");
		printf("UdpLowBurstPeriodNS=%" PRIu64 "\n", conf->burst_period_ns);
		printf("UdpLowNumFramesPerCycle=%zu\n", conf->num_frames_per_cycle);
		printf("UdpLowPayloadPattern=");
		print_payload_pattern(conf->payload_pattern, conf->payload_pattern_length);
		printf("\n");
		printf("UdpLowFrameLength=%zu\n", conf->frame_length);
		printf("UdpLowRxQueue=%d\n", conf->rx_queue);
		printf("UdpLowTxQueue=%d\n", conf->tx_queue);
		printf("UdpLowSocketPriority=%d\n", conf->socket_priority);
		printf("UdpLowTxThreadPriority=%d\n", conf->tx_thread_priority);
		printf("UdpLowRxThreadPriority=%d\n", conf->rx_thread_priority);
		printf("UdpLowTxThreadCpu=%d\n", conf->tx_thread_cpu);
		printf("UdpLowRxThreadCpu=%d\n", conf->rx_thread_cpu);
		printf("UdpLowInterface=%s\n", conf->interface);
		printf("UdpLowPort=%s\n", conf->l3_port);
		printf("UdpLowDestination=%s\n", conf->l3_destination);
		printf("UdpLowSource=%s\n", conf->l3_source);
		printf("---------------------------------------------------------------------------"
		       "-----\n");
	}

	conf = &app_config.classes[GENERICL2_FRAME_TYPE];
	if (config_is_traffic_class_active("GenericL2")) {
		printf("GenericL2Name=%s\n", conf->name);
		printf("GenericL2Enabled=%s\n", conf->enabled ? "True" : "False");
		printf("GenericL2RxMirrorEnabled=%s\n", conf->rx_mirror_enabled ? "True" : "False");
		printf("GenericL2XdpEnabled=%s\n", conf->xdp_enabled ? "True" : "False");
		printf("GenericL2XdpSkbMode=%s\n", conf->xdp_skb_mode ? "True" : "False");
		printf("GenericL2XdpZcMode=%s\n", conf->xdp_zc_mode ? "True" : "False");
		printf("GenericL2XdpWakeupMode=%s\n", conf->xdp_wakeup_mode ? "True" : "False");
		printf("GenericL2XdpBusyPollMode=%s\n",
		       conf->xdp_busy_poll_mode ? "True" : "False");
		printf("GenericL2TxTimeEnabled=%s\n", conf->tx_time_enabled ? "True" : "False");
		printf("GenericL2IgnoreRxErrors=%s\n", conf->ignore_rx_errors ? "True" : "False");
		printf("GenericL2TxTimeOffsetNS=%" PRIu64 "\n", conf->tx_time_offset_ns);
		printf("GenericL2TxTimeStampEnabled=%s\n",
		       conf->tx_hwtstamp_enabled ? "True" : "False");
		printf("GenericL2Vid=%d\n", conf->vid);
		printf("GenericL2Pcp=%d\n", conf->pcp);
		printf("GenericL2EtherType=0x%04x\n", conf->ether_type);
		printf("GenericL2NumFramesPerCycle=%zu\n", conf->num_frames_per_cycle);
		printf("GenericL2PayloadPattern=");
		print_payload_pattern(conf->payload_pattern, conf->payload_pattern_length);
		printf("\n");
		printf("GenericL2FrameLength=%zu\n", conf->frame_length);
		printf("GenericL2RxQueue=%d\n", conf->rx_queue);
		printf("GenericL2TxQueue=%d\n", conf->tx_queue);
		printf("GenericL2SocketPriority=%d\n", conf->socket_priority);
		printf("GenericL2TxThreadPriority=%d\n", conf->tx_thread_priority);
		printf("GenericL2RxThreadPriority=%d\n", conf->rx_thread_priority);
		printf("GenericL2TxThreadCpu=%d\n", conf->tx_thread_cpu);
		printf("GenericL2RxThreadCpu=%d\n", conf->rx_thread_cpu);
		printf("GenericL2Interface=%s\n", conf->interface);
		printf("GenericL2Destination=");
		print_mac_address(conf->l2_destination);
		printf("GenericL2RxWorkloadEnabled=%s\n",
		       conf->rx_workload_enabled ? "True" : "False");
		printf("GenericL2RxWorkloadPrewarm=%s\n",
		       conf->rx_workload_prewarm ? "True" : "False");
		printf("GenericL2RxWorkloadSkipCount=%d\n", conf->rx_workload_skip_count);
		printf("GenericL2RxWorkloadFile=%s\n", conf->workload_file);
		printf("GenericL2RxWorkloadSetupFunction=%s\n", conf->workload_setup_function);
		printf("GenericL2RxWorkloadSetupArguments=%s\n", conf->workload_setup_arguments);
		printf("GenericL2RxWorkloadFunction=%s\n", conf->workload_function);
		printf("GenericL2RxWorkloadArguments=%s\n", conf->workload_arguments);
		printf("GenericL2RxWorkloadThreadCpu=%d\n", conf->workload_thread_cpu);
		printf("GenericL2RxWorkloadThreadPriority=%d\n", conf->workload_thread_priority);
		printf("\n");
		printf("---------------------------------------------------------------------------"
		       "-----\n");
	}

	printf("LogThreadPriority=%d\n", app_config.log_thread_priority);
	printf("LogThreadCpu=%d\n", app_config.log_thread_cpu);
	printf("LogFile=%s\n", app_config.log_file);
	printf("LogLevel=%s\n", app_config.log_level);
	printf("--------------------------------------------------------------------------------"
	       "\n");

	printf("DebugStopTraceOnOutlier=%s\n",
	       app_config.debug_stop_trace_on_outlier ? "True" : "False");
	printf("DebugStopTraceOnError=%s\n",
	       app_config.debug_stop_trace_on_error ? "True" : "False");
	printf("DebugMonitorMode=%s\n", app_config.debug_monitor_mode ? "True" : "False");
	printf("DebugMonitorDestination=");
	print_mac_address(app_config.debug_monitor_destination);
	printf("\n");
	printf("--------------------------------------------------------------------------------"
	       "\n");

	if (app_config.stats_histogram_enabled) {
		printf("StatsHistogramEnabled=%s\n",
		       app_config.stats_histogram_enabled ? "True" : "False");
		printf("StatsHistogramMinimumNS=%" PRIu64 "\n",
		       app_config.stats_histogram_minimum_ns);
		printf("StatsHistogramMaximumNS=%" PRIu64 "\n",
		       app_config.stats_histogram_maximum_ns);
		printf("StatsHistogramFile=%s\n", app_config.stats_histogram_file);
		printf("StatsCollectionIntervalNS=%" PRIu64 "\n",
		       app_config.stats_collection_interval_ns);
		printf("---------------------------------------------------------------------------"
		       "-----\n");
	}

	if (app_config.log_mqtt) {
		printf("LogMqtt=%s\n", app_config.log_mqtt ? "True" : "False");
		printf("LogMqttThreadPriority=%d\n", app_config.log_mqtt_thread_priority);
		printf("LogMqttThreadCpu=%d\n", app_config.log_mqtt_thread_cpu);
		printf("LogMqttBrokerIP=%s\n", app_config.log_mqtt_broker_ip);
		printf("LogMqttBrokerPort=%d\n", app_config.log_mqtt_broker_port);
		printf("LogMqttKeepAliveSecs=%d\n", app_config.log_mqtt_keep_alive_secs);
		printf("LogMqttMeasurementName=%s\n", app_config.log_mqtt_measurement_name);
		printf("---------------------------------------------------------------------------"
		       "-----\n");
	}

	if (app_config.log_json) {
		printf("LogJson=%s\n", app_config.log_json ? "True" : "False");
		printf("LogJsonThreadPriority=%d\n", app_config.log_json_thread_priority);
		printf("LogJsonThreadCpu=%d\n", app_config.log_json_thread_cpu);
		printf("LogJsonHost=%s\n", app_config.log_json_host);
		printf("LogJsonPort=%s\n", app_config.log_json_port);
		printf("LogJsonMeasurementName=%s\n", app_config.log_json_measurement_name);
		printf("---------------------------------------------------------------------------"
		       "-----\n");
	}
}

int config_set_defaults(bool mirror_enabled)
{
	static unsigned char default_debug_montitor_destination[] = {0x44, 0x44, 0x44,
								     0x44, 0x44, 0x44};
	static unsigned char default_lldp_destination[] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e};
	static unsigned char default_destination[] = {0xa8, 0xa1, 0x59, 0x2c, 0xa8, 0xdb};
	static unsigned char default_dcp_identify[] = {0x01, 0x0e, 0xcf, 0x00, 0x00, 0x00};
	static const char *default_log_mqtt_measurement_name = "reference";
	static const char *default_udp_low_destination = "192.168.2.120";
	static const char *default_log_mqtt_broker_ip = "127.0.0.1";
	static const char *default_udp_low_source = "192.168.2.119";
	static const char *default_payload_pattern = "Payload";
	static const char *default_hist_file = "histogram.txt";
	static const char *default_json_host = "localhost";
	static const char *default_udp_low_port = "6666";
	static const char *default_json_port = "58415";
	static const char *default_log_level = "Debug";
	struct traffic_class_config *conf;
	struct timespec current;
	int ret = -ENOMEM;

	clock_gettime(CLOCK_TAI, &current);

	/* Application scheduling configuration */
	app_config.application_clock_id = CLOCK_TAI;
	app_config.application_base_cycle_time_ns = 500000;
	app_config.application_base_start_time_ns = (current.tv_sec + 30) * NSEC_PER_SEC;
	app_config.application_base_start_offset_ns = 0;
	app_config.application_tx_base_offset_ns = 400000;
	app_config.application_rx_base_offset_ns = 200000;
	app_config.application_xdp_program = NULL;

	/* TSN High */
	conf = &app_config.classes[TSN_HIGH_FRAME_TYPE];
	conf->enabled = false;
	conf->rx_mirror_enabled = mirror_enabled;
	conf->xdp_enabled = false;
	conf->xdp_skb_mode = false;
	conf->xdp_zc_mode = false;
	conf->xdp_wakeup_mode = true;
	conf->xdp_busy_poll_mode = false;
	conf->tx_time_enabled = false;
	conf->ignore_rx_errors = false;
	conf->tx_time_offset_ns = 0;
	conf->tx_hwtstamp_enabled = false;
	conf->vid = TSN_HIGH_VID_VALUE;
	conf->pcp = TSN_HIGH_PCP_VALUE;
	conf->num_frames_per_cycle = 0;
	conf->payload_pattern = strdup(default_payload_pattern);
	if (!conf->payload_pattern)
		goto out;
	conf->payload_pattern_length = strlen(conf->payload_pattern);
	conf->frame_length = 200;
	conf->security_mode = SECURITY_MODE_NONE;
	conf->security_algorithm = SECURITY_ALGORITHM_AES256_GCM;
	conf->security_key = NULL;
	conf->security_iv_prefix = NULL;
	conf->rx_queue = 1;
	conf->tx_queue = 1;
	conf->socket_priority = 1;
	conf->tx_thread_priority = 98;
	conf->rx_thread_priority = 98;
	conf->tx_thread_cpu = 0;
	conf->rx_thread_cpu = 0;
	conf->rx_workload_enabled = false;
	conf->rx_workload_prewarm = false;
	conf->rx_workload_skip_count = 0;
	conf->workload_file = NULL;
	conf->workload_function = NULL;
	conf->workload_arguments = NULL;
	conf->workload_setup_function = NULL;
	conf->workload_setup_arguments = NULL;
	conf->workload_thread_cpu = 0;
	conf->workload_thread_priority = 98;
	strncpy(conf->interface, "enp3s0", sizeof(conf->interface) - 1);
	memcpy((void *)conf->l2_destination, default_destination, ETH_ALEN);

	/* TSN Low */
	conf = &app_config.classes[TSN_LOW_FRAME_TYPE];
	conf->enabled = false;
	conf->rx_mirror_enabled = mirror_enabled;
	conf->xdp_enabled = false;
	conf->xdp_skb_mode = false;
	conf->xdp_zc_mode = false;
	conf->xdp_wakeup_mode = true;
	conf->xdp_busy_poll_mode = false;
	conf->tx_time_enabled = false;
	conf->ignore_rx_errors = false;
	conf->tx_time_offset_ns = 0;
	conf->tx_hwtstamp_enabled = false;
	conf->vid = TSN_LOW_VID_VALUE;
	conf->pcp = TSN_LOW_PCP_VALUE;
	conf->num_frames_per_cycle = 0;
	conf->payload_pattern = strdup(default_payload_pattern);
	if (!conf->payload_pattern)
		goto out;
	conf->payload_pattern_length = strlen(conf->payload_pattern);
	conf->frame_length = 200;
	conf->security_mode = SECURITY_MODE_NONE;
	conf->security_algorithm = SECURITY_ALGORITHM_AES256_GCM;
	conf->security_key = NULL;
	conf->security_iv_prefix = NULL;
	conf->rx_queue = 1;
	conf->tx_queue = 1;
	conf->socket_priority = 1;
	conf->tx_thread_priority = 98;
	conf->rx_thread_priority = 98;
	conf->tx_thread_cpu = 0;
	conf->rx_thread_cpu = 0;
	strncpy(conf->interface, "enp3s0", sizeof(conf->interface) - 1);
	memcpy((void *)conf->l2_destination, default_destination, ETH_ALEN);

	/* Real Time Cyclic (RTC) */
	conf = &app_config.classes[RTC_FRAME_TYPE];
	conf->enabled = false;
	conf->rx_mirror_enabled = mirror_enabled;
	conf->xdp_enabled = false;
	conf->xdp_skb_mode = false;
	conf->xdp_zc_mode = false;
	conf->xdp_wakeup_mode = true;
	conf->xdp_busy_poll_mode = false;
	conf->ignore_rx_errors = false;
	conf->tx_hwtstamp_enabled = false;
	conf->vid = PROFINET_RT_VID_VALUE;
	conf->pcp = RTC_PCP_VALUE;
	conf->num_frames_per_cycle = 0;
	conf->payload_pattern = strdup(default_payload_pattern);
	if (!conf->payload_pattern)
		goto out;
	conf->payload_pattern_length = strlen(conf->payload_pattern);
	conf->frame_length = 200;
	conf->security_mode = SECURITY_MODE_NONE;
	conf->security_algorithm = SECURITY_ALGORITHM_AES256_GCM;
	conf->security_key = NULL;
	conf->security_iv_prefix = NULL;
	conf->rx_queue = 1;
	conf->tx_queue = 1;
	conf->socket_priority = 1;
	conf->tx_thread_priority = 98;
	conf->rx_thread_priority = 98;
	conf->tx_thread_cpu = 0;
	conf->rx_thread_cpu = 0;
	conf->rx_workload_enabled = false;
	conf->rx_workload_prewarm = false;
	conf->rx_workload_skip_count = 0;
	conf->workload_file = NULL;
	conf->workload_function = NULL;
	conf->workload_arguments = NULL;
	conf->workload_setup_function = NULL;
	conf->workload_setup_arguments = NULL;
	conf->workload_thread_cpu = 0;
	conf->workload_thread_priority = 98;
	strncpy(conf->interface, "enp3s0", sizeof(conf->interface) - 1);
	memcpy((void *)conf->l2_destination, default_destination, ETH_ALEN);

	/* Real Time Acyclic (RTA) */
	conf = &app_config.classes[RTA_FRAME_TYPE];
	conf->enabled = false;
	conf->rx_mirror_enabled = mirror_enabled;
	conf->xdp_enabled = false;
	conf->xdp_skb_mode = false;
	conf->xdp_zc_mode = false;
	conf->xdp_wakeup_mode = true;
	conf->xdp_busy_poll_mode = false;
	conf->ignore_rx_errors = false;
	conf->tx_hwtstamp_enabled = false;
	conf->vid = PROFINET_RT_VID_VALUE;
	conf->pcp = RTA_PCP_VALUE;
	conf->burst_period_ns = 200000000;
	conf->num_frames_per_cycle = 0;
	conf->payload_pattern = strdup(default_payload_pattern);
	if (!conf->payload_pattern)
		goto out;
	conf->payload_pattern_length = strlen(conf->payload_pattern);
	conf->frame_length = 200;
	conf->security_mode = SECURITY_MODE_NONE;
	conf->security_algorithm = SECURITY_ALGORITHM_AES256_GCM;
	conf->security_key = NULL;
	conf->security_iv_prefix = NULL;
	conf->rx_queue = 1;
	conf->tx_queue = 1;
	conf->socket_priority = 1;
	conf->tx_thread_priority = 98;
	conf->rx_thread_priority = 98;
	conf->tx_thread_cpu = 0;
	conf->rx_thread_cpu = 0;
	strncpy(conf->interface, "enp3s0", sizeof(conf->interface) - 1);
	memcpy((void *)conf->l2_destination, default_destination, ETH_ALEN);

	/* Discovery and Configuration Protocol (DCP) */
	conf = &app_config.classes[DCP_FRAME_TYPE];
	conf->enabled = false;
	conf->ignore_rx_errors = false;
	conf->rx_mirror_enabled = mirror_enabled;
	conf->vid = PROFINET_RT_VID_VALUE;
	conf->pcp = DCP_PCP_VALUE;
	conf->burst_period_ns = 2000000000;
	conf->num_frames_per_cycle = 0;
	conf->payload_pattern = strdup(default_payload_pattern);
	if (!conf->payload_pattern)
		goto out;
	conf->payload_pattern_length = strlen(conf->payload_pattern);
	conf->frame_length = 200;
	conf->rx_queue = 1;
	conf->tx_queue = 1;
	conf->socket_priority = 1;
	conf->tx_thread_priority = 98;
	conf->rx_thread_priority = 98;
	conf->tx_thread_cpu = 3;
	conf->rx_thread_cpu = 3;
	strncpy(conf->interface, "enp3s0", sizeof(conf->interface) - 1);
	memcpy((void *)conf->l2_destination, default_dcp_identify, ETH_ALEN);

	/* Link Layer Discovery Protocol (LLDP) */
	conf = &app_config.classes[LLDP_FRAME_TYPE];
	conf->enabled = false;
	conf->ignore_rx_errors = false;
	conf->rx_mirror_enabled = mirror_enabled;
	conf->burst_period_ns = 5000000000;
	conf->num_frames_per_cycle = 0;
	conf->payload_pattern = strdup(default_payload_pattern);
	if (!conf->payload_pattern)
		goto out;
	conf->payload_pattern_length = strlen(conf->payload_pattern);
	conf->frame_length = 200;
	conf->rx_queue = 1;
	conf->tx_queue = 1;
	conf->socket_priority = 1;
	conf->tx_thread_priority = 98;
	conf->rx_thread_priority = 98;
	conf->tx_thread_cpu = 4;
	conf->rx_thread_cpu = 4;
	strncpy(conf->interface, "enp3s0", sizeof(conf->interface) - 1);
	memcpy((void *)conf->l2_destination, default_lldp_destination, ETH_ALEN);

	/* User Datagram Protocol (UDP) High */
	conf = &app_config.classes[UDP_HIGH_FRAME_TYPE];
	conf->enabled = false;
	conf->ignore_rx_errors = false;
	conf->rx_mirror_enabled = mirror_enabled;
	conf->burst_period_ns = 1000000000;
	conf->num_frames_per_cycle = 0;
	conf->payload_pattern = strdup(default_payload_pattern);
	if (!conf->payload_pattern)
		goto out;
	conf->payload_pattern_length = strlen(conf->payload_pattern);
	conf->frame_length = 1400;
	conf->rx_queue = 0;
	conf->tx_queue = 0;
	conf->socket_priority = 0;
	conf->tx_thread_priority = 98;
	conf->rx_thread_priority = 98;
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

	/* User Datagram Protocol (UDP) Low */
	conf = &app_config.classes[UDP_LOW_FRAME_TYPE];
	conf->enabled = false;
	conf->ignore_rx_errors = false;
	conf->rx_mirror_enabled = mirror_enabled;
	conf->burst_period_ns = 1000000000;
	conf->num_frames_per_cycle = 0;
	conf->payload_pattern = strdup(default_payload_pattern);
	if (!conf->payload_pattern)
		goto out;
	conf->payload_pattern_length = strlen(conf->payload_pattern);
	conf->frame_length = 1400;
	conf->rx_queue = 0;
	conf->tx_queue = 0;
	conf->socket_priority = 0;
	conf->tx_thread_priority = 98;
	conf->rx_thread_priority = 98;
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

	/* Generic L2 */
	conf = &app_config.classes[GENERICL2_FRAME_TYPE];
	conf->name = strdup("GenericL2");
	if (!conf->name)
		goto out;
	conf->enabled = false;
	conf->rx_mirror_enabled = mirror_enabled;
	conf->xdp_enabled = false;
	conf->xdp_skb_mode = false;
	conf->xdp_zc_mode = false;
	conf->xdp_wakeup_mode = true;
	conf->xdp_busy_poll_mode = false;
	conf->tx_time_enabled = false;
	conf->ignore_rx_errors = false;
	conf->tx_time_offset_ns = 0;
	conf->tx_hwtstamp_enabled = false;
	conf->vid = 100;
	conf->pcp = 6;
	conf->ether_type = 0xb62c;
	conf->num_frames_per_cycle = 0;
	conf->payload_pattern = strdup(default_payload_pattern);
	if (!conf->payload_pattern)
		goto out;
	conf->payload_pattern_length = strlen(conf->payload_pattern);
	conf->frame_length = 200;
	conf->rx_queue = 1;
	conf->tx_queue = 1;
	conf->socket_priority = 1;
	conf->tx_thread_priority = 90;
	conf->rx_thread_priority = 90;
	conf->tx_thread_cpu = 0;
	conf->rx_thread_cpu = 0;
	conf->rx_workload_enabled = false;
	conf->rx_workload_prewarm = false;
	conf->rx_workload_skip_count = 0;
	conf->workload_file = NULL;
	conf->workload_function = NULL;
	conf->workload_arguments = NULL;
	conf->workload_setup_function = NULL;
	conf->workload_setup_arguments = NULL;
	conf->workload_thread_cpu = 0;
	conf->workload_thread_priority = 98;
	strncpy(conf->interface, "enp3s0", sizeof(conf->interface) - 1);
	memcpy((void *)conf->l2_destination, default_destination, ETH_ALEN);

	/* Logging */
	app_config.log_thread_priority = 1;
	app_config.log_thread_cpu = 7;
	app_config.log_file = strdup("reference.log");
	if (!app_config.log_file)
		goto out;
	app_config.log_level = strdup(default_log_level);
	if (!app_config.log_level)
		goto out;

	/* Debug */
	app_config.debug_stop_trace_on_outlier = false;
	app_config.debug_stop_trace_on_error = false;
	app_config.debug_monitor_mode = false;
	memcpy((void *)app_config.debug_monitor_destination, default_debug_montitor_destination,
	       ETH_ALEN);

	/* Stats */
	app_config.stats_histogram_enabled = false;
	app_config.stats_histogram_minimum_ns = 1 * 1e6;
	app_config.stats_histogram_maximum_ns = 10 * 1e6;
	app_config.stats_histogram_file = strdup(default_hist_file);
	if (!app_config.stats_histogram_file)
		goto out;
	app_config.stats_histogram_file_length = strlen(default_hist_file);
	app_config.stats_collection_interval_ns = 1e9;

	/* LogMqtt */
	app_config.log_mqtt = false;
	app_config.log_mqtt_broker_port = 1883;
	app_config.log_mqtt_thread_priority = 1;
	app_config.log_mqtt_thread_cpu = 7;
	app_config.log_mqtt_keep_alive_secs = 60;
	app_config.log_mqtt_broker_ip = strdup(default_log_mqtt_broker_ip);
	if (!app_config.log_mqtt_broker_ip)
		goto out;
	app_config.log_mqtt_measurement_name = strdup(default_log_mqtt_measurement_name);
	if (!app_config.log_mqtt_measurement_name)
		goto out;

	app_config.log_json = false;
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
	if (config_is_traffic_class_active("GenericL2") &&
	    (config_is_traffic_class_active("TsnHigh") ||
	     config_is_traffic_class_active("TsnLow") || config_is_traffic_class_active("Rtc") ||
	     config_is_traffic_class_active("Rta") || config_is_traffic_class_active("Dcp") ||
	     config_is_traffic_class_active("Lldp") || config_is_traffic_class_active("UdpHigh") ||
	     config_is_traffic_class_active("UdpLow"))) {
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

	return true;
}

void config_free(void)
{
	free(app_config.application_xdp_program);

	free(app_config.classes[TSN_HIGH_FRAME_TYPE].payload_pattern);
	free(app_config.classes[TSN_HIGH_FRAME_TYPE].security_key);
	free(app_config.classes[TSN_HIGH_FRAME_TYPE].security_iv_prefix);

	free(app_config.classes[TSN_LOW_FRAME_TYPE].payload_pattern);
	free(app_config.classes[TSN_LOW_FRAME_TYPE].security_key);
	free(app_config.classes[TSN_LOW_FRAME_TYPE].security_iv_prefix);

	free(app_config.classes[RTC_FRAME_TYPE].payload_pattern);
	free(app_config.classes[RTC_FRAME_TYPE].security_key);
	free(app_config.classes[RTC_FRAME_TYPE].security_iv_prefix);

	free(app_config.classes[RTA_FRAME_TYPE].payload_pattern);
	free(app_config.classes[RTA_FRAME_TYPE].security_key);
	free(app_config.classes[RTA_FRAME_TYPE].security_iv_prefix);

	free(app_config.classes[DCP_FRAME_TYPE].payload_pattern);

	free(app_config.classes[LLDP_FRAME_TYPE].payload_pattern);

	free(app_config.classes[UDP_HIGH_FRAME_TYPE].payload_pattern);
	free(app_config.classes[UDP_HIGH_FRAME_TYPE].l3_port);
	free(app_config.classes[UDP_HIGH_FRAME_TYPE].l3_destination);
	free(app_config.classes[UDP_HIGH_FRAME_TYPE].l3_source);

	free(app_config.classes[UDP_LOW_FRAME_TYPE].payload_pattern);
	free(app_config.classes[UDP_LOW_FRAME_TYPE].l3_port);
	free(app_config.classes[UDP_LOW_FRAME_TYPE].l3_destination);
	free(app_config.classes[UDP_LOW_FRAME_TYPE].l3_source);

	free(app_config.classes[GENERICL2_FRAME_TYPE].name);
	free(app_config.classes[GENERICL2_FRAME_TYPE].payload_pattern);

	free(app_config.stats_histogram_file);

	free(app_config.log_file);
	free(app_config.log_level);

	free(app_config.log_mqtt_broker_ip);
	free(app_config.log_mqtt_measurement_name);

	free(app_config.log_json_host);
	free(app_config.log_json_port);
	free(app_config.log_json_measurement_name);
}
