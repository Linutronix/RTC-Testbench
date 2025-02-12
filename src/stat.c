// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2021-2024 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#include <errno.h>
#include <inttypes.h>
#include <memory.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "config.h"
#include "hist.h"
#include "log.h"
#include "logviamqtt.h"
#include "stat.h"
#include "utils.h"

struct statistics global_statistics[NUM_FRAME_TYPES];
static struct statistics statistics_per_period[NUM_FRAME_TYPES];
static struct round_trip_context round_trip_contexts[NUM_FRAME_TYPES];
static uint64_t rtt_expected_rt_limit;
static int log_stat_user_selected;
static FILE *file_tracing_on;
static FILE *file_trace_marker;

const char *stat_frame_type_names[NUM_FRAME_TYPES] = {
	"TsnHigh", "TsnLow", "Rtc", "Rta", "Dcp", "Lldp", "UdpHigh", "UdpLow", "GenericL2"};

/*
 * Keep 1024 periods of backlog available. If a frame is received later than 1024 periods after
 * sending, it's a bug in any case.
 *
 * E.g. A period of 500us results in a backlog of 500ms.
 */
#define STAT_MAX_BACKLOG 1024

static void stat_reset(struct statistics *stats)
{
	memset(stats, 0, sizeof(struct statistics));
	stats->round_trip_min = UINT64_MAX;
	stats->oneway_min = UINT64_MAX;
}

int stat_init(enum log_stat_options log_selection)
{
	int i;

	if (log_selection >= LOG_NUM_OPTIONS)
		return -EINVAL;

	if (log_selection == LOG_REFERENCE) {
		bool allocation_error = false;

		round_trip_contexts[TSN_HIGH_FRAME_TYPE].backlog_len =
			STAT_MAX_BACKLOG *
			app_config.classes[TSN_HIGH_FRAME_TYPE].num_frames_per_cycle;
		round_trip_contexts[TSN_LOW_FRAME_TYPE].backlog_len =
			STAT_MAX_BACKLOG *
			app_config.classes[TSN_LOW_FRAME_TYPE].num_frames_per_cycle;
		round_trip_contexts[RTC_FRAME_TYPE].backlog_len =
			STAT_MAX_BACKLOG * app_config.classes[RTC_FRAME_TYPE].num_frames_per_cycle;
		round_trip_contexts[RTA_FRAME_TYPE].backlog_len =
			STAT_MAX_BACKLOG * app_config.classes[RTA_FRAME_TYPE].num_frames_per_cycle;
		round_trip_contexts[DCP_FRAME_TYPE].backlog_len =
			STAT_MAX_BACKLOG * app_config.classes[DCP_FRAME_TYPE].num_frames_per_cycle;
		round_trip_contexts[LLDP_FRAME_TYPE].backlog_len =
			STAT_MAX_BACKLOG * app_config.classes[LLDP_FRAME_TYPE].num_frames_per_cycle;
		round_trip_contexts[UDP_HIGH_FRAME_TYPE].backlog_len =
			STAT_MAX_BACKLOG *
			app_config.classes[UDP_HIGH_FRAME_TYPE].num_frames_per_cycle;
		round_trip_contexts[UDP_LOW_FRAME_TYPE].backlog_len =
			STAT_MAX_BACKLOG *
			app_config.classes[UDP_LOW_FRAME_TYPE].num_frames_per_cycle;
		round_trip_contexts[GENERICL2_FRAME_TYPE].backlog_len =
			STAT_MAX_BACKLOG *
			app_config.classes[GENERICL2_FRAME_TYPE].num_frames_per_cycle;

		for (i = 0; i < NUM_FRAME_TYPES; i++) {
			struct round_trip_context *current_context = &round_trip_contexts[i];

			current_context->backlog =
				calloc(current_context->backlog_len, sizeof(int64_t));
			allocation_error |= !current_context->backlog;
		}

		if (allocation_error)
			return -ENOMEM;
	}

	for (i = 0; i < NUM_FRAME_TYPES; i++) {
		stat_reset(&global_statistics[i]);
		stat_reset(&statistics_per_period[i]);
	}

	if (app_config.debug_stop_trace_on_outlier) {
		file_tracing_on = fopen("/sys/kernel/debug/tracing/tracing_on", "w");
		if (!file_tracing_on)
			return -errno;
		file_trace_marker = fopen("/sys/kernel/debug/tracing/trace_marker", "w");
		if (!file_trace_marker) {
			fclose(file_tracing_on);
			return -errno;
		}
	}

	/*
	 * The expected round trip limit for RT traffic classes is below < 2 * cycle time.
	 * Stored in us.
	 */
	rtt_expected_rt_limit = app_config.application_base_cycle_time_ns * 2;
	rtt_expected_rt_limit /= 1000;

	log_stat_user_selected = log_selection;

	return 0;
}

void stat_free(void)
{

	for (int i = 0; i < NUM_FRAME_TYPES; i++)
		free(round_trip_contexts[i].backlog);

	if (app_config.debug_stop_trace_on_outlier) {
		fclose(file_tracing_on);
		fclose(file_trace_marker);
	}
}

static inline void stat_update_min_max(uint64_t new_value, uint64_t *min, uint64_t *max)
{
	*max = (new_value > *max) ? new_value : *max;
	*min = (new_value < *min) ? new_value : *min;
}

static bool stat_frame_received_common(struct statistics *stat, enum stat_frame_type frame_type,
				       uint64_t rt_time, uint64_t oneway_time, bool out_of_order,
				       bool payload_mismatch, bool frame_id_mismatch)
{
	bool outlier = false;

	if (log_stat_user_selected == LOG_REFERENCE) {
		if (stat_frame_type_is_real_time(frame_type) && rt_time > rtt_expected_rt_limit) {
			stat->round_trip_outliers++;
			outlier = true;
		}

		stat_update_min_max(rt_time, &stat->round_trip_min, &stat->round_trip_max);

		stat->round_trip_count++;
		stat->round_trip_sum += rt_time;
		stat->round_trip_avg = stat->round_trip_sum / (double)stat->round_trip_count;
	}

	stat_update_min_max(oneway_time, &stat->oneway_min, &stat->oneway_max);

	if (stat_frame_type_is_real_time(frame_type) && oneway_time > rtt_expected_rt_limit / 2) {
		stat->oneway_outliers++;
		outlier = true;
	}
	stat->oneway_count++;
	stat->oneway_sum += oneway_time;
	stat->oneway_avg = stat->oneway_sum / (double)stat->oneway_count;

	stat->frames_received++;
	stat->out_of_order_errors += out_of_order;
	stat->payload_errors += payload_mismatch;
	stat->frame_id_errors += frame_id_mismatch;

	return outlier;
}

#if defined(WITH_MQTT)
static void stat_frame_received_per_period(enum stat_frame_type frame_type, uint64_t curr_time,
					   uint64_t rt_time, uint64_t oneway_time,
					   bool out_of_order, bool payload_mismatch,
					   bool frame_id_mismatch)
{
	struct statistics *stat_per_period = &statistics_per_period[frame_type];
	uint64_t elapsed;

	if (stat_per_period->first_time_stamp == 0)
		stat_per_period->first_time_stamp = curr_time;

	/*
	 * Test if the amount of time specified in the config is arrived. If true this will be the
	 * last point to be taken into stats per period.
	 */
	elapsed = curr_time - stat_per_period->first_time_stamp;
	if (elapsed >= app_config.stats_collection_interval_ns) {
		stat_per_period->ready = true;
		stat_per_period->last_time_stamp = curr_time;
	}

	stat_frame_received_common(stat_per_period, frame_type, rt_time, oneway_time, out_of_order,
				   payload_mismatch, frame_id_mismatch);

	/* Copy stats for MQTT module. */
	if (stat_per_period->ready) {
		log_via_mqtt_stats(frame_type, &statistics_per_period[frame_type]);
		stat_reset(&statistics_per_period[frame_type]);
	}
}

static void stat_frame_sent_per_period(enum stat_frame_type frame_type)
{
	struct statistics *stat_per_period = &statistics_per_period[frame_type];

	/* Just increment the Tx counter. The reset per period is done by the Rx part. */
	stat_per_period->frames_sent++;
}
#else
static void stat_frame_received_per_period(enum stat_frame_type frame_type, uint64_t curr_time,
					   uint64_t rt_time, bool out_of_order,
					   bool payload_mismatch, bool frame_id_mismatch,
					   uint64_t tx_timestamp)
{
}

static void stat_frame_sent_per_period(enum stat_frame_type frame_type)
{
}
#endif

void stat_frame_sent(enum stat_frame_type frame_type, uint64_t cycle_number)
{
	struct round_trip_context *rtt = &round_trip_contexts[frame_type];
	struct statistics *stat = &global_statistics[frame_type];
	struct timespec tx_time = {};

	log_message(LOG_LEVEL_DEBUG, "%s: frame[%" PRIu64 "] sent\n",
		    stat_frame_type_to_string(frame_type), cycle_number);

	if (log_stat_user_selected == LOG_REFERENCE) {
		/* Record Tx timestamp in */
		clock_gettime(app_config.application_clock_id, &tx_time);
		rtt->backlog[cycle_number % rtt->backlog_len] = ts_to_ns(&tx_time);
	}

	/* Increment stats */
	stat_frame_sent_per_period(frame_type);
	stat->frames_sent++;
}

void stat_frame_received(enum stat_frame_type frame_type, uint64_t cycle_number, bool out_of_order,
			 bool payload_mismatch, bool frame_id_mismatch, uint64_t tx_timestamp)
{
	struct round_trip_context *rtt = &round_trip_contexts[frame_type];
	const bool histogram = app_config.stats_histogram_enabled;
	struct statistics *stat = &global_statistics[frame_type];
	uint64_t rt_time = 0, curr_time, oneway_time;
	struct timespec rx_time = {};
	bool outlier = false;

	log_message(LOG_LEVEL_DEBUG, "%s: frame[%" PRIu64 "] received\n",
		    stat_frame_type_to_string(frame_type), cycle_number);

	/* Record Rx timestamp in us */
	clock_gettime(app_config.application_clock_id, &rx_time);
	curr_time = ts_to_ns(&rx_time);

	if (log_stat_user_selected == LOG_REFERENCE) {
		/* Calc Round Trip Time */
		rt_time = curr_time - rtt->backlog[cycle_number % rtt->backlog_len];
		rt_time /= 1000;

		/* Update histogram */
		if (histogram)
			histogram_update(frame_type, rt_time);
	}

	/* Calc Oneway Time */
	oneway_time = curr_time - tx_timestamp;
	oneway_time /= 1000;

	/* Update global stats */
	outlier = stat_frame_received_common(stat, frame_type, rt_time, oneway_time, out_of_order,
					     payload_mismatch, frame_id_mismatch);

	/* Update stats per collection interval */
	stat_frame_received_per_period(frame_type, curr_time, rt_time, oneway_time, out_of_order,
				       payload_mismatch, frame_id_mismatch);

	/* Stop tracing after certain amount of time */
	if (app_config.debug_stop_trace_on_outlier && outlier) {
		fprintf(file_trace_marker,
			"Outlier hit: %" PRIu64 " [us] -- Type: %s -- Cycle Counter: %" PRIu64 "\n",
			rt_time ? rt_time : oneway_time, stat_frame_type_to_string(frame_type),
			cycle_number);
		fprintf(file_tracing_on, "0\n");
		fprintf(stderr,
			"Outlier hit: %" PRIu64 " [us] -- Type: %s -- Cycle Counter: %" PRIu64 "\n",
			rt_time ? rt_time : oneway_time, stat_frame_type_to_string(frame_type),
			cycle_number);
		fclose(file_trace_marker);
		fclose(file_tracing_on);
		exit(EXIT_SUCCESS);
	}
}
