/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2021-2025 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#ifndef _STAT_H_
#define _STAT_H_

#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum log_stat_options {
	LOG_REFERENCE = 0,
	LOG_MIRROR,
	/* Mirror mode with TX timestamping enabled */
	LOG_TX_TIMESTAMPS,
	LOG_NUM_OPTIONS
};

enum stat_frame_type {
	TSN_HIGH_FRAME_TYPE = 0,
	TSN_LOW_FRAME_TYPE,
	RTC_FRAME_TYPE,
	RTA_FRAME_TYPE,
	DCP_FRAME_TYPE,
	LLDP_FRAME_TYPE,
	UDP_HIGH_FRAME_TYPE,
	UDP_LOW_FRAME_TYPE,
	GENERICL2_FRAME_TYPE,
	NUM_FRAME_TYPES,
};

static inline bool stat_frame_type_is_real_time(enum stat_frame_type frame_type)
{
	switch (frame_type) {
	case TSN_HIGH_FRAME_TYPE:
	case TSN_LOW_FRAME_TYPE:
	case RTC_FRAME_TYPE:
	case GENERICL2_FRAME_TYPE:
		return true;
	default:
		return false;
	}
}

extern const char *stat_frame_type_names[NUM_FRAME_TYPES];

static inline const char *stat_frame_type_to_string(enum stat_frame_type frame_type)
{
	return stat_frame_type_names[frame_type];
}

struct statistics {
	uint64_t time_stamp;
	uint64_t frames_sent;
	uint64_t frames_received;
	uint64_t out_of_order_errors;
	uint64_t frame_id_errors;
	uint64_t payload_errors;
	uint64_t round_trip_min;
	uint64_t round_trip_max;
	uint64_t round_trip_count;
	uint64_t round_trip_outliers;
	double round_trip_sum;
	double round_trip_avg;
	uint64_t oneway_min;
	uint64_t oneway_max;
	uint64_t oneway_count;
	uint64_t oneway_outliers;
	double oneway_sum;
	double oneway_avg;
	/* First-frame processing latency at Mirror (1st Rx HW to 1st Tx HW timestamp) */
	uint64_t proc_first_min;
	uint64_t proc_first_max;
	uint64_t proc_first_count;
	uint64_t proc_first_outliers;
	double proc_first_sum;
	double proc_first_avg;
	/* Batch processing latency at Mirror (1st Rx HW to Last Tx HW timestamp) */
	uint64_t proc_batch_min;
	uint64_t proc_batch_max;
	uint64_t proc_batch_count;
	uint64_t proc_batch_outliers;
	double proc_batch_sum;
	double proc_batch_avg;
	/* Rx latency from NIC Rx Hw timestamp to user space timestamp */
	uint64_t rx_min;
	uint64_t rx_max;
	double rx_sum;
	double rx_avg;
	/* Rx latency from NIC Rx Hw timestamp to Xdp prog timestamp */
	uint64_t rx_hw2xdp_min;
	uint64_t rx_hw2xdp_max;
	double rx_hw2xdp_sum;
	double rx_hw2xdp_avg;
	/* Rx latency from Xdp prog timestamp to user space timestamp */
	uint64_t rx_xdp2app_min;
	uint64_t rx_xdp2app_max;
	double rx_xdp2app_sum;
	double rx_xdp2app_avg;
	/* Workload statistics */
	uint64_t rx_workload_min;
	uint64_t rx_workload_max;
	uint64_t rx_workload_count;
	double rx_workload_sum;
	double rx_workload_avg;
	uint64_t rx_workload_outliers;
	/* Tx latency from user space (at send) to NIC Tx HW timestamp */
	uint64_t tx_min;
	uint64_t tx_max;
	uint64_t tx_count;
	uint64_t tx_hw_timestamp_missing;
	double tx_sum;
	double tx_avg;
};

struct rtt_entry {
	uint64_t sw_ts;
	uint64_t hw_ts;
	uint64_t rx_hw_ts;
};

struct round_trip_context {
	struct rtt_entry *backlog;
	size_t backlog_len;
};

int stat_init(enum log_stat_options log_selection);
void stat_free(void);
const char *stat_frame_type_to_string(enum stat_frame_type frame_type);
void stat_frame_sent(enum stat_frame_type frame_type, uint64_t cycle_number);
void stat_frames_sent_batch(enum stat_frame_type frame_type, uint64_t cycle_number,
			    uint64_t frame_count);
void stat_frame_received(enum stat_frame_type frame_type, uint64_t cycle_number, bool out_of_order,
			 bool payload_mismatch, bool frame_id_mismatch, uint64_t tx_timestamp,
			 uint64_t rx_hw_timestamp, uint64_t rx_sw_timestamp);
void stat_update(void);
void stat_get_global_stats(struct statistics *stats, size_t len);
void stat_get_stats_per_period(struct statistics *stats, size_t len);
void stat_frame_workload(enum stat_frame_type, uint64_t cycle_number, struct timespec start_ts);
void stat_inc_workload_outlier(enum stat_frame_type frame_type);
void stat_frame_sent_latency(enum stat_frame_type frame_type, uint64_t seq);
void stat_proc_first_latency(enum stat_frame_type frame_type, uint64_t cycle_number,
			     uint64_t tx_hw_timestamp);
void stat_proc_batch_latency(enum stat_frame_type frame_type, uint64_t cycle_number,
			     uint64_t last_tx_hw_timestamp);
int stat_to_json(char *json, size_t len, const struct statistics *stat, const char *tc,
		 const char *measurement);

extern volatile sig_atomic_t reset_stats;
extern struct round_trip_context round_trip_contexts[NUM_FRAME_TYPES];
extern int log_stat_user_selected;

#endif /* _STAT_H_ */
