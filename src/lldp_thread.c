// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2020-2025 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>

#include "config.h"
#include "lldp_thread.h"
#include "log.h"
#include "net.h"
#include "net_def.h"
#include "packet.h"
#include "security.h"
#include "stat.h"
#include "thread.h"
#include "utils.h"

static void lldp_build_frame_from_rx(unsigned char *frame_data, const unsigned char *source)
{
	struct ethhdr *eth = (struct ethhdr *)frame_data;
	struct reference_meta_data *meta;

	/* One task: Swap source. */
	memcpy(eth->h_source, source, ETH_ALEN);

	/* One task: Set the tx timestamp. */
	meta = (struct reference_meta_data *)(frame_data + sizeof(*eth));
	set_mirror_tx_timestamp(meta);
}

static void lldp_initialize_frame(struct thread_context *thread_context, unsigned char *frame_data,
				  const unsigned char *source, const unsigned char *destination)
{
	const struct traffic_class_config *lldp_config = thread_context->conf;
	struct reference_meta_data *meta;
	size_t payload_offset;
	struct ethhdr *eth;

	/*
	 * LldpFrame:
	 *   Destination (multicast)
	 *   Source
	 *   Ether type: 88cc
	 *   Cycle counter
	 *   Payload
	 *   Padding to maxFrame
	 */

	eth = (struct ethhdr *)frame_data;

	/* Ethernet header */
	memcpy(eth->h_dest, destination, ETH_ALEN);
	memcpy(eth->h_source, source, ETH_ALEN);
	eth->h_proto = htons(ETH_P_LLDP);

	/* Payload: SequenceCounter + Data */
	meta = (struct reference_meta_data *)(frame_data + sizeof(*eth));
	memset(meta, '\0', sizeof(*meta));
	payload_offset = sizeof(*eth) + sizeof(*meta);
	memcpy(frame_data + payload_offset, lldp_config->payload_pattern,
	       lldp_config->payload_pattern_length);

	/* Padding: '\0' */
}

static void lldp_initialize_frames(struct thread_context *thread_context, unsigned char *frame_data,
				   size_t num_frames, const unsigned char *source,
				   const unsigned char *destination)
{
	size_t i;

	for (i = 0; i < num_frames; i++)
		lldp_initialize_frame(thread_context, frame_idx(frame_data, i), source,
				      destination);
}

static int lldp_send_messages(struct thread_context *thread_context, int socket_fd,
			      struct sockaddr_ll *destination, unsigned char *frame_data,
			      size_t num_frames)
{
	const struct traffic_class_config *lldp_config = thread_context->conf;
	struct packet_send_request send_req = {
		.traffic_class = thread_context->traffic_class,
		.socket_fd = socket_fd,
		.destination = destination,
		.frame_data = frame_data,
		.num_frames = num_frames,
		.frame_length = lldp_config->frame_length,
		.duration = 0,
		.tx_time_offset = 0,
		.meta_data_offset = thread_context->meta_data_offset,
		.mirror_enabled = lldp_config->rx_mirror_enabled,
		.tx_time_enabled = false,
	};

	return packet_send_messages(thread_context->packet_context, &send_req);
}

static int lldp_send_frames(struct thread_context *thread_context, unsigned char *frame_data,
			    size_t num_frames, int socket_fd, struct sockaddr_ll *destination)
{
	const struct traffic_class_config *lldp_config = thread_context->conf;
	int len, i;

	/* Send them */
	len = lldp_send_messages(thread_context, socket_fd, destination, frame_data, num_frames);

	for (i = 0; i < len; i++) {
		uint64_t sequence_counter;

		sequence_counter = get_sequence_counter(frame_data + i * lldp_config->frame_length,
							thread_context->meta_data_offset,
							lldp_config->num_frames_per_cycle);

		stat_frame_sent(LLDP_FRAME_TYPE, sequence_counter);
	}

	return len;
}

static int lldp_gen_and_send_frames(struct thread_context *thread_context, int socket_fd,
				    struct sockaddr_ll *destination,
				    uint64_t sequence_counter_begin)
{
	const struct traffic_class_config *lldp_config = thread_context->conf;
	struct reference_meta_data *meta;
	struct timespec tx_time = {};
	struct ethhdr *eth;
	int len, i;

	clock_gettime(app_config.application_clock_id, &tx_time);

	/* Adjust meta data */
	for (i = 0; i < lldp_config->num_frames_per_cycle; i++) {
		meta = (struct reference_meta_data *)(frame_idx(thread_context->tx_frame_data, i) +
						      sizeof(*eth));
		sequence_counter_to_meta_data(meta, sequence_counter_begin + i,
					      lldp_config->num_frames_per_cycle);

		tx_timestamp_to_meta_data(meta, ts_to_ns(&tx_time));
	}

	/* Send them */
	len = lldp_send_messages(thread_context, socket_fd, destination,
				 thread_context->tx_frame_data, lldp_config->num_frames_per_cycle);

	for (i = 0; i < len; i++)
		stat_frame_sent(LLDP_FRAME_TYPE, sequence_counter_begin + i);

	return len;
}

static void *lldp_tx_thread_routine(void *data)
{
	struct thread_context *thread_context = data;
	const struct traffic_class_config *lldp_config = thread_context->conf;
	size_t received_frames_length = MAX_FRAME_SIZE * lldp_config->num_frames_per_cycle;
	unsigned char *received_frames = thread_context->rx_frame_data;
	const bool mirror_enabled = lldp_config->rx_mirror_enabled;
	pthread_mutex_t *mutex = &thread_context->data_mutex;
	pthread_cond_t *cond = &thread_context->data_cond_var;
	struct sockaddr_ll destination;
	unsigned char source[ETH_ALEN];
	uint64_t sequence_counter = 0;
	unsigned int if_index;
	int ret, socket_fd;

	socket_fd = thread_context->socket_fd;

	ret = get_interface_mac_address(lldp_config->interface, source, ETH_ALEN);
	if (ret < 0) {
		log_message(LOG_LEVEL_ERROR, "LldpTx: Failed to get Source MAC address!\n");
		return NULL;
	}

	if_index = if_nametoindex(lldp_config->interface);
	if (!if_index) {
		log_message(LOG_LEVEL_ERROR, "LldpTx: if_nametoindex() failed!\n");
		return NULL;
	}

	memset(&destination, '\0', sizeof(destination));
	destination.sll_family = PF_PACKET;
	destination.sll_ifindex = if_index;
	destination.sll_halen = ETH_ALEN;
	memcpy(destination.sll_addr, lldp_config->l2_destination, ETH_ALEN);

	lldp_initialize_frames(thread_context, thread_context->tx_frame_data,
			       lldp_config->num_frames_per_cycle, source,
			       lldp_config->l2_destination);

	while (!thread_context->stop) {
		struct timespec timeout;
		size_t num_frames;

		/*
		 * Wait until signalled. These LLDP frames have to be sent after the DCP
		 * frames. Therefore, the DCP TxThread signals this one here.
		 */
		clock_gettime(CLOCK_MONOTONIC, &timeout);
		timeout.tv_sec++;

		pthread_mutex_lock(mutex);
		ret = pthread_cond_timedwait(cond, mutex, &timeout);
		num_frames = thread_context->num_frames_available;
		thread_context->num_frames_available = 0;
		pthread_mutex_unlock(mutex);

		/* In case of shutdown a signal may be missing. */
		if (ret == ETIMEDOUT)
			continue;

		/*
		 * Send LldpFrames, two possibilites:
		 *  a) Generate it, or
		 *  b) Use received ones if mirror enabled
		 */
		if (!mirror_enabled) {
			if (num_frames) {
				lldp_gen_and_send_frames(thread_context, socket_fd, &destination,
							 sequence_counter);
				sequence_counter += num_frames;
			}
		} else {
			size_t len;

			ring_buffer_fetch(thread_context->mirror_buffer, received_frames,
					  received_frames_length, &len);

			/* Len should be a multiple of frame size */
			num_frames = len / lldp_config->frame_length;
			lldp_send_frames(thread_context, received_frames, num_frames, socket_fd,
					 &destination);

			pthread_mutex_lock(&thread_context->data_mutex);
			thread_context->num_frames_available = 0;
			pthread_mutex_unlock(&thread_context->data_mutex);
		}

		/* Signal next Tx thread */
		if (thread_context->next) {
			pthread_mutex_lock(&thread_context->next->data_mutex);
			pthread_cond_signal(&thread_context->next->data_cond_var);
			pthread_mutex_unlock(&thread_context->next->data_mutex);
		}

		if (thread_context->is_last)
			stat_update();
	}

	return NULL;
}

static int lldp_rx_frame(void *data, unsigned char *frame_data, size_t len)
{
	struct thread_context *thread_context = data;
	const struct traffic_class_config *lldp_config = thread_context->conf;
	const unsigned char *expected_pattern = (const unsigned char *)lldp_config->payload_pattern;
	const size_t expected_pattern_length = lldp_config->payload_pattern_length;
	const size_t num_frames_per_cycle = lldp_config->num_frames_per_cycle;
	const bool mirror_enabled = lldp_config->rx_mirror_enabled;
	const bool ignore_rx_errors = lldp_config->ignore_rx_errors;
	const size_t frame_length = lldp_config->frame_length;
	bool out_of_order, payload_mismatch, frame_id_mismatch;
	struct reference_meta_data *meta;
	uint64_t sequence_counter;
	uint64_t tx_timestamp;

	/* Process received frame. */
	if (len != frame_length) {
		log_message(LOG_LEVEL_WARNING, "LldpRx: Frame with wrong length received!\n");
		return -EINVAL;
	}

	/*
	 * Check cycle counter and payload. The ether type is checked by the
	 * attached BPF filter.
	 */
	meta = (struct reference_meta_data *)(frame_data + sizeof(struct ethhdr));
	sequence_counter = meta_data_to_sequence_counter(meta, num_frames_per_cycle);

	tx_timestamp = meta_data_to_tx_timestamp(meta);

	out_of_order = sequence_counter != thread_context->rx_sequence_counter;
	payload_mismatch = memcmp(frame_data + sizeof(struct ethhdr) + sizeof(*meta),
				  expected_pattern, expected_pattern_length);
	frame_id_mismatch = false;

	stat_frame_received(LLDP_FRAME_TYPE, sequence_counter, out_of_order, payload_mismatch,
			    frame_id_mismatch, tx_timestamp, 0, 0);

	if (out_of_order) {
		if (!ignore_rx_errors)
			log_message(LOG_LEVEL_WARNING,
				    "LldpRx: frame[%" PRIu64 "] SequenceCounter mismatch: %" PRIu64
				    "!\n",
				    sequence_counter, thread_context->rx_sequence_counter);
		thread_context->rx_sequence_counter++;
	}

	if (payload_mismatch)
		log_message(LOG_LEVEL_WARNING,
			    "LldpRx: frame[%" PRIu64 "] Payload Pattern mismatch!\n",
			    sequence_counter);

	thread_context->rx_sequence_counter++;

	/* If mirror enabled, assemble and store the frame for Tx later. */
	if (!mirror_enabled)
		return 0;

	/* Build new frame for Tx without VLAN info. */
	lldp_build_frame_from_rx(frame_data, thread_context->source);

	/* Store the new frame. */
	ring_buffer_add(thread_context->mirror_buffer, frame_data, len);

	pthread_mutex_lock(&thread_context->data_mutex);
	thread_context->num_frames_available++;
	pthread_mutex_unlock(&thread_context->data_mutex);

	return 0;
}

static void *lldp_rx_thread_routine(void *data)
{
	struct thread_context *thread_context = data;
	const struct traffic_class_config *lldp_config = thread_context->conf;
	const uint64_t cycle_time_ns = app_config.application_base_cycle_time_ns;
	struct timespec wakeup_time;
	int socket_fd, ret;

	socket_fd = thread_context->socket_fd;

	ret = get_interface_mac_address(lldp_config->interface, thread_context->source, ETH_ALEN);
	if (ret < 0) {
		log_message(LOG_LEVEL_ERROR, "LldpRx: Failed to get Source MAC address!\n");
		return NULL;
	}

	ret = get_thread_start_time(app_config.application_rx_base_offset_ns, &wakeup_time);
	if (ret) {
		log_message(LOG_LEVEL_ERROR, "LldpRx: Failed to calculate thread start time: %s!\n",
			    strerror(errno));
		return NULL;
	}

	while (!thread_context->stop) {
		struct packet_receive_request recv_req = {
			.traffic_class = thread_context->traffic_class,
			.socket_fd = socket_fd,
			.receive_function = lldp_rx_frame,
			.data = thread_context,
		};

		/* Wait until next period. */
		increment_period(&wakeup_time, cycle_time_ns);

		do {
			ret = clock_nanosleep(app_config.application_clock_id, TIMER_ABSTIME,
					      &wakeup_time, NULL);
		} while (ret == EINTR);

		if (ret) {
			log_message(LOG_LEVEL_ERROR, "LldpRx: clock_nanosleep() failed: %s\n",
				    strerror(ret));
			return NULL;
		}

		/* Receive Lldp frames. */
		packet_receive_messages(thread_context->packet_context, &recv_req);
	}

	return NULL;
}

static void *lldp_tx_generation_thread_routine(void *data)
{
	struct thread_context *thread_context = data;
	const struct traffic_class_config *lldp_config = thread_context->conf;
	uint64_t num_frames = lldp_config->num_frames_per_cycle;
	pthread_mutex_t *mutex = &thread_context->data_mutex;
	uint64_t cycle_time_ns = lldp_config->burst_period_ns;
	struct timespec wakeup_time;
	int ret;

	/*
	 * The LLDP frames are generated by bursts with a certain period. This thread is responsible
	 * for generating it.
	 */

	ret = get_thread_start_time(0, &wakeup_time);
	if (ret) {
		log_message(LOG_LEVEL_ERROR,
			    "LldpTxGen: Failed to calculate thread start time: %s!\n",
			    strerror(errno));
		return NULL;
	}

	while (!thread_context->stop) {
		/* Wait until next period */
		increment_period(&wakeup_time, cycle_time_ns);

		do {
			ret = clock_nanosleep(app_config.application_clock_id, TIMER_ABSTIME,
					      &wakeup_time, NULL);
		} while (ret == EINTR);

		if (ret) {
			log_message(LOG_LEVEL_ERROR, "LldpTxGen: clock_nanosleep() failed: %s\n",
				    strerror(ret));
			return NULL;
		}

		/* Generate frames */
		pthread_mutex_lock(mutex);
		thread_context->num_frames_available = num_frames;
		pthread_mutex_unlock(mutex);
	}

	return NULL;
}

int lldp_threads_create(struct thread_context *thread_context)
{
	struct traffic_class_config *lldp_config;
	int ret;

	if (!config_is_traffic_class_active("Lldp"))
		goto out;

	thread_context->conf = lldp_config = &app_config.classes[LLDP_FRAME_TYPE];
	thread_context->frame_type = LLDP_FRAME_TYPE;
	thread_context->traffic_class = stat_frame_type_to_string(LLDP_FRAME_TYPE);

	thread_context->socket_fd = create_lldp_socket();
	if (thread_context->socket_fd < 0) {
		fprintf(stderr, "Failed to create LldpSocket!\n");
		ret = -errno;
		goto err;
	}

	init_mutex(&thread_context->data_mutex);
	init_condition_variable(&thread_context->data_cond_var);

	thread_context->packet_context = packet_init(lldp_config->num_frames_per_cycle);
	if (!thread_context->packet_context) {
		fprintf(stderr, "Failed to allocate Lldp packet context!\n");
		ret = -ENOMEM;
		goto err_packet;
	}

	thread_context->tx_frame_data = calloc(lldp_config->num_frames_per_cycle, MAX_FRAME_SIZE);
	if (!thread_context->tx_frame_data) {
		fprintf(stderr, "Failed to allocate LldpTxFrameData!\n");
		ret = -ENOMEM;
		goto err_tx;
	}

	thread_context->rx_frame_data = calloc(lldp_config->num_frames_per_cycle, MAX_FRAME_SIZE);
	if (!thread_context->rx_frame_data) {
		fprintf(stderr, "Failed to allocate LldpRxFrameData!\n");
		ret = -ENOMEM;
		goto err_rx;
	}

	if (lldp_config->rx_mirror_enabled) {
		/* Per period the expectation is: LldpNumFramesPerCycle * MAX_FRAME */
		thread_context->mirror_buffer =
			ring_buffer_allocate(MAX_FRAME_SIZE * lldp_config->num_frames_per_cycle);
		if (!thread_context->mirror_buffer) {
			fprintf(stderr, "Failed to allocate Lldp Mirror RingBuffer!\n");
			ret = -ENOMEM;
			goto err_buffer;
		}
	}

	ret = create_rt_thread(&thread_context->tx_task_id, "LldpTxThread",
			       lldp_config->tx_thread_priority, lldp_config->tx_thread_cpu,
			       lldp_tx_thread_routine, thread_context);
	if (ret) {
		fprintf(stderr, "Failed to create Lldp Tx Thread!\n");
		goto err_thread;
	}

	if (!lldp_config->rx_mirror_enabled) {
		ret = create_rt_thread(&thread_context->tx_gen_task_id, "LldpTxGenThread",
				       lldp_config->tx_thread_priority, lldp_config->tx_thread_cpu,
				       lldp_tx_generation_thread_routine, thread_context);
		if (ret) {
			fprintf(stderr, "Failed to create Lldp TxGen Thread!\n");
			goto err_thread_txgen;
		}
	}

	ret = create_rt_thread(&thread_context->rx_task_id, "LldpRxThread",
			       lldp_config->rx_thread_priority, lldp_config->rx_thread_cpu,
			       lldp_rx_thread_routine, thread_context);
	if (ret) {
		fprintf(stderr, "Failed to create Lldp Rx Thread!\n");
		goto err_thread_rx;
	}

	thread_context->meta_data_offset =
		get_meta_data_offset(LLDP_FRAME_TYPE, SECURITY_MODE_NONE);

out:
	ret = 0;

	return ret;

err_thread_rx:
	thread_context->stop = 1;
	if (thread_context->tx_gen_task_id)
		pthread_join(thread_context->tx_gen_task_id, NULL);
err_thread_txgen:
	thread_context->stop = 1;
	pthread_join(thread_context->tx_task_id, NULL);
err_thread:
	ring_buffer_free(thread_context->mirror_buffer);
err_buffer:
	free(thread_context->rx_frame_data);
err_rx:
	free(thread_context->tx_frame_data);
err_tx:
	packet_free(thread_context->packet_context);
err_packet:
	close(thread_context->socket_fd);
err:
	return ret;
}

void lldp_threads_free(struct thread_context *thread_context)
{
	if (!thread_context)
		return;

	ring_buffer_free(thread_context->mirror_buffer);

	packet_free(thread_context->packet_context);
	free(thread_context->tx_frame_data);
	free(thread_context->rx_frame_data);

	if (thread_context->socket_fd > 0)
		close(thread_context->socket_fd);
}

void lldp_threads_wait_for_finish(struct thread_context *thread_context)
{
	if (!thread_context)
		return;

	if (thread_context->rx_task_id)
		pthread_join(thread_context->rx_task_id, NULL);
	if (thread_context->tx_task_id)
		pthread_join(thread_context->tx_task_id, NULL);
	if (thread_context->tx_gen_task_id)
		pthread_join(thread_context->tx_gen_task_id, NULL);
}
