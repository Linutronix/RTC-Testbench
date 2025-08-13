// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2021-2025 Linutronix GmbH
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
#include "thread.h"
#include "utils.h"

/*
 * This is used by all real time Tx and Rx threads. However, all threads have their own portion
 * within that struct so that it can be accessed without taking any locks. That is a must, because
 * Tx and Rx are hot paths and we do not want to wait for logging or such.
 */
static struct statistics global_statistics[NUM_FRAME_TYPES];

/*
 * Once per stat collection interval the global_statistics are copied to global_statistics_for_log
 * for the log threads. That is used for file Log at the moment.
 */
static struct statistics global_statistics_for_log[NUM_FRAME_TYPES];
static pthread_mutex_t global_statistics_mutex;

/*
 * These structs contains only the statistics for current stat interval. This is used by MQTT.
 */
static struct statistics statistics_per_period[NUM_FRAME_TYPES];
static struct statistics statistics_per_period_for_log[NUM_FRAME_TYPES];

struct round_trip_context round_trip_contexts[NUM_FRAME_TYPES];
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

/*
 * If SIGUSR1 signal is received, reset the global statistics.
 */
volatile sig_atomic_t reset_stats = 0;

static void stat_reset(struct statistics *stats)
{
	memset(stats, 0, sizeof(struct statistics));
	stats->round_trip_min = UINT64_MAX;
	stats->oneway_min = UINT64_MAX;
	stats->rx_min = UINT64_MAX;
	stats->rx_hw2xdp_min = UINT64_MAX;
	stats->rx_xdp2app_min = UINT64_MAX;
	stats->tx_min = UINT64_MAX;
}

int stat_init(enum log_stat_options log_selection)
{
	int i;

	if (log_selection >= LOG_NUM_OPTIONS)
		return -EINVAL;

	init_mutex(&global_statistics_mutex);

	if (log_selection == LOG_REFERENCE || log_selection == LOG_TX_TIMESTAMPS) {
		bool allocation_error = false;

		for (i = 0; i < NUM_FRAME_TYPES; i++) {
			bool needs_backlog = (log_selection == LOG_REFERENCE) ||
					     (log_selection == LOG_TX_TIMESTAMPS &&
					      app_config.classes[i].tx_hwtstamp_enabled);

			if (needs_backlog) {
				struct round_trip_context *current_context =
					&round_trip_contexts[i];

				current_context->backlog_len =
					STAT_MAX_BACKLOG *
					app_config.classes[i].num_frames_per_cycle;

				current_context->backlog = calloc(current_context->backlog_len,
								  sizeof(struct rtt_entry));
				allocation_error |= !current_context->backlog;
			}
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

/*
 * This function will be called once per cycle after all Tx threads have been finished. At this
 * point in time no one touches global_statistics, because all networking is done.
 *
 * It copies all *statistics to *statistics_for_log.
 */
void stat_update(void)
{
	static uint64_t last_ts = 0;
	uint64_t elapsed, curr_time;
	bool proceed = false;
	struct timespec now;

	clock_gettime(app_config.application_clock_id, &now);
	curr_time = ts_to_ns(&now);

	if (!last_ts)
		last_ts = curr_time;

	elapsed = curr_time - last_ts;
	if (elapsed >= app_config.stats_collection_interval_ns) {
		proceed = true;
		last_ts = curr_time;
	}

	if (!proceed)
		return;

	/* Update stats for logging facilities. */
	pthread_mutex_lock(&global_statistics_mutex);
	memcpy(&global_statistics_for_log, &global_statistics, sizeof(global_statistics));
#if defined(WITH_MQTT)
	memcpy(&statistics_per_period_for_log, &statistics_per_period,
	       sizeof(statistics_per_period));
	for (int i = 0; i < NUM_FRAME_TYPES; i++)
		stat_reset(&statistics_per_period[i]);
#endif
	pthread_mutex_unlock(&global_statistics_mutex);

	/* Perform reset of global statistics if requested by user. */
	if (reset_stats) {
		for (int i = 0; i < NUM_FRAME_TYPES; i++)
			stat_reset(&global_statistics[i]);
		reset_stats = 0;
	}
}

void stat_get_global_stats(struct statistics *stats, size_t len)
{
	if (len < sizeof(global_statistics_for_log))
		return;

	pthread_mutex_lock(&global_statistics_mutex);
	memcpy(stats, &global_statistics_for_log, sizeof(global_statistics_for_log));
	pthread_mutex_unlock(&global_statistics_mutex);
}

void stat_get_stats_per_period(struct statistics *stats, size_t len)
{
	if (len < sizeof(statistics_per_period_for_log))
		return;

	pthread_mutex_lock(&global_statistics_mutex);
	memcpy(stats, &statistics_per_period_for_log, sizeof(statistics_per_period_for_log));
	pthread_mutex_unlock(&global_statistics_mutex);
}

static inline void stat_update_min_max(uint64_t new_value, uint64_t *min, uint64_t *max)
{
	*max = (new_value > *max) ? new_value : *max;
	*min = (new_value < *min) ? new_value : *min;
}

static bool stat_frame_received_common(struct statistics *stat, enum stat_frame_type frame_type,
				       uint64_t rt_time, uint64_t oneway_time, bool out_of_order,
				       bool payload_mismatch, bool frame_id_mismatch,
				       uint64_t rx_hw2app_time, uint64_t rx_hw2xdp_time,
				       uint64_t rx_xdp2app_time)
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

	if (rx_hw2app_time != 0 && rx_hw2xdp_time != 0 && rx_xdp2app_time != 0) {
		stat_update_min_max(rx_hw2app_time, &stat->rx_min, &stat->rx_max);
		stat->rx_sum += rx_hw2app_time;
		stat->rx_avg = stat->rx_sum / (double)stat->oneway_count;

		stat_update_min_max(rx_hw2xdp_time, &stat->rx_hw2xdp_min, &stat->rx_hw2xdp_max);
		stat->rx_hw2xdp_sum += rx_hw2xdp_time;
		stat->rx_hw2xdp_avg = stat->rx_hw2xdp_sum / (double)stat->oneway_count;

		stat_update_min_max(rx_xdp2app_time, &stat->rx_xdp2app_min, &stat->rx_xdp2app_max);
		stat->rx_xdp2app_sum += rx_xdp2app_time;
		stat->rx_xdp2app_avg = stat->rx_xdp2app_sum / (double)stat->oneway_count;
	}

	stat->frames_received++;
	stat->out_of_order_errors += out_of_order;
	stat->payload_errors += payload_mismatch;
	stat->frame_id_errors += frame_id_mismatch;

	return outlier;
}

#ifdef TX_TIMESTAMP
static void stat_frame_sent_latency_common(struct statistics *stat, enum stat_frame_type frame_type,
					   uint64_t tx_latency_us)
{
	stat_update_min_max(tx_latency_us, &stat->tx_min, &stat->tx_max);

	stat->tx_count++;
	stat->tx_sum += tx_latency_us;
	stat->tx_avg = stat->tx_sum / (double)stat->tx_count;
}
#endif

#if defined(WITH_MQTT)
static void stat_frame_received_per_period(enum stat_frame_type frame_type, uint64_t curr_time,
					   uint64_t rt_time, uint64_t oneway_time,
					   bool out_of_order, bool payload_mismatch,
					   bool frame_id_mismatch, uint64_t rx_hw2app_time,
					   uint64_t rx_hw2xdp_time, uint64_t rx_xdp2app_time)
{
	struct statistics *stat_per_period = &statistics_per_period[frame_type];

	stat_per_period->time_stamp = curr_time;
	stat_frame_received_common(stat_per_period, frame_type, rt_time, oneway_time, out_of_order,
				   payload_mismatch, frame_id_mismatch, rx_hw2app_time,
				   rx_hw2xdp_time, rx_xdp2app_time);
}

static void stat_frame_sent_per_period(enum stat_frame_type frame_type)
{
	struct statistics *stat_per_period = &statistics_per_period[frame_type];

	/* Just increment the Tx counter. The reset per period is done by the Rx part. */
	stat_per_period->frames_sent++;
}

#ifdef TX_TIMESTAMP
static void stat_frame_sent_latency_per_period(enum stat_frame_type frame_type,
					       uint64_t tx_latency_us)
{
	struct statistics *stat_per_period = &statistics_per_period[frame_type];

	stat_frame_sent_latency_common(stat_per_period, frame_type, tx_latency_us);
}
#endif
#else
static void stat_frame_received_per_period(enum stat_frame_type frame_type, uint64_t curr_time,
					   uint64_t rt_time, bool out_of_order,
					   bool payload_mismatch, bool frame_id_mismatch,
					   uint64_t tx_timestamp, uint64_t rx_hw2app_time,
					   uint64_t rx_hw2xdp_time, uint64_t rx_xdp2app_time)
{
}

static void stat_frame_sent_per_period(enum stat_frame_type frame_type)
{
}

#ifdef TX_TIMESTAMP
static void stat_frame_sent_latency_per_period(enum stat_frame_type frame_type,
					       uint64_t tx_latency_us)
{
}
#endif
#endif

void stat_frame_sent(enum stat_frame_type frame_type, uint64_t cycle_number)
{
	/* Single frame is just a batch operation with count=1 */
	stat_frames_sent_batch(frame_type, cycle_number, 1);
}

void stat_frames_sent_batch(enum stat_frame_type frame_type, uint64_t cycle_number,
			    uint64_t frame_count)
{
	struct round_trip_context *rtt = &round_trip_contexts[frame_type];
	struct statistics *stat = &global_statistics[frame_type];
	size_t idx = cycle_number % rtt->backlog_len;
	struct timespec tx_time = {};

	if (frame_count == 1) {
		log_message(LOG_LEVEL_DEBUG, "%s: frame[%" PRIu64 "] sent\n",
			    stat_frame_type_to_string(frame_type), cycle_number);
	} else {
		log_message(LOG_LEVEL_DEBUG, "%s: %" PRIu64 " frames[%" PRIu64 "] sent\n",
			    stat_frame_type_to_string(frame_type), frame_count, cycle_number);
	}

	if ((log_stat_user_selected == LOG_REFERENCE ||
	     log_stat_user_selected == LOG_TX_TIMESTAMPS) &&
	    rtt->backlog) {
		/* Record Tx SW timestamp for the first frame in the cycle */
		clock_gettime(app_config.application_clock_id, &tx_time);
		rtt->backlog[idx].sw_ts = ts_to_ns(&tx_time);
	}

	/* Increment stats by frame_count */
	for (uint64_t i = 0; i < frame_count; i++) {
		stat_frame_sent_per_period(frame_type);
	}
	stat->frames_sent += frame_count;
}

#ifdef TX_TIMESTAMP
void stat_frame_sent_latency(enum stat_frame_type frame_type, uint64_t seq)
{
	bool hwtstamp_enabled = app_config.classes[frame_type].tx_hwtstamp_enabled;
	struct statistics *stat_per_period = &statistics_per_period[frame_type];
	struct round_trip_context *rtt = &round_trip_contexts[frame_type];
	struct statistics *stat = &global_statistics[frame_type];
	size_t idx = seq % rtt->backlog_len;
	uint64_t sw_ts = rtt->backlog[idx].sw_ts;
	uint64_t hw_ts = rtt->backlog[idx].hw_ts;

	if (!hwtstamp_enabled) {
		log_message(LOG_LEVEL_INFO,
			    "TxLatency [%s] HW timestamping disabled — skipping Tx latency stat\n",
			    stat_frame_type_to_string(frame_type));
		return;
	}

	if (hw_ts > sw_ts) {
		int64_t latency = (int64_t)(hw_ts - sw_ts);

		latency /= 1000;

		log_message(LOG_LEVEL_DEBUG,
			    "TxLatency [%s] Seq %" PRIu64
			    ": SW %llu ns, HW %llu ns, latency %lld us, idx=%zu\n",
			    stat_frame_type_to_string(frame_type), seq, (unsigned long long)sw_ts,
			    (unsigned long long)hw_ts, (long long)latency, idx);

		/* Update global stats */
		stat_frame_sent_latency_common(stat, frame_type, latency);

		/* Update stats per collection interval */
		stat_frame_sent_latency_per_period(frame_type, latency);

	} else {
		/* HW timestamp missing — update both global & per-period */
		stat->tx_hw_timestamp_missing++;
		stat_per_period->tx_hw_timestamp_missing++;

		log_message(LOG_LEVEL_DEBUG,
			    "TxLatency [%s] Seq %" PRIu64
			    ": No HW Tx timestamp for SW %llu ns, idx=%zu\n",
			    stat_frame_type_to_string(frame_type), seq, (unsigned long long)sw_ts,
			    idx);
	}
}
#endif

void stat_frame_received(enum stat_frame_type frame_type, uint64_t cycle_number, bool out_of_order,
			 bool payload_mismatch, bool frame_id_mismatch, uint64_t tx_timestamp,
			 uint64_t rx_hw_timestamp, uint64_t rx_sw_timestamp)
{
	struct round_trip_context *rtt = &round_trip_contexts[frame_type];
	const bool histogram = app_config.stats_histogram_enabled;
	struct statistics *stat = &global_statistics[frame_type];
	uint64_t rt_time = 0, curr_time, oneway_time, rx_hw2app_time, rx_hw2xdp_time,
		 rx_xdp2app_time;
	struct timespec rx_time = {};
	bool outlier = false;

	log_message(LOG_LEVEL_DEBUG, "%s: frame[%" PRIu64 "] received\n",
		    stat_frame_type_to_string(frame_type), cycle_number);

	/* Record Rx timestamp in us */
	clock_gettime(app_config.application_clock_id, &rx_time);
	curr_time = ts_to_ns(&rx_time);

	if (log_stat_user_selected == LOG_REFERENCE) {
		uint64_t tx_sw_ts;
		size_t backlog_idx;

		/* Determine which timestamp to use based on TX HW timestamp configuration */
		if (app_config.classes[frame_type].tx_hwtstamp_enabled) {
			/*
			 * When TX HW timestamping is enabled, only first frame of each cycle has
			 * timestamp
			 */
			uint64_t first_frame_in_cycle =
				(cycle_number /
				 app_config.classes[frame_type].num_frames_per_cycle) *
				app_config.classes[frame_type].num_frames_per_cycle;
			backlog_idx = first_frame_in_cycle % rtt->backlog_len;
			tx_sw_ts = rtt->backlog[backlog_idx].sw_ts;
		} else {
			/* When TX HW timestamping is disabled, each frame has its own timestamp */
			backlog_idx = cycle_number % rtt->backlog_len;
			tx_sw_ts = rtt->backlog[backlog_idx].sw_ts;
		}

		/* Calc Round Trip Time */
		if (tx_sw_ts != 0) {
			rt_time = curr_time - tx_sw_ts;
			rt_time /= 1000;
		} else {
			rt_time = 0;
		}

		/* Update histogram */
		if (histogram)
			histogram_update(frame_type, rt_time);
	}

	/* Calc Oneway Time */
	oneway_time = curr_time - tx_timestamp;
	oneway_time /= 1000;

	if (rx_hw_timestamp != 0 && rx_sw_timestamp != 0) {
		/* Calculate Rx times */
		rx_hw2app_time = curr_time - rx_hw_timestamp;
		rx_hw2app_time /= 1000;
		rx_hw2xdp_time = rx_sw_timestamp - rx_hw_timestamp;
		rx_hw2xdp_time /= 1000;
		rx_xdp2app_time = curr_time - rx_sw_timestamp;
		rx_xdp2app_time /= 1000;
	} else {
		/* If one of the timestamp is not available, set them to zero */
		rx_hw2app_time = 0;
		rx_hw2xdp_time = 0;
		rx_xdp2app_time = 0;
	}

	/* Update global stats */
	outlier = stat_frame_received_common(stat, frame_type, rt_time, oneway_time, out_of_order,
					     payload_mismatch, frame_id_mismatch, rx_hw2app_time,
					     rx_hw2xdp_time, rx_xdp2app_time);

	/* Update stats per collection interval */
	stat_frame_received_per_period(frame_type, curr_time, rt_time, oneway_time, out_of_order,
				       payload_mismatch, frame_id_mismatch, rx_hw2app_time,
				       rx_hw2xdp_time, rx_xdp2app_time);

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
