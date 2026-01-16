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
#include <linux/if_vlan.h>

#include "config.h"
#include "dcp_thread.h"
#include "log.h"
#include "net.h"
#include "packet.h"
#include "profinet.h"
#include "security.h"
#include "stat.h"
#include "utils.h"

static void dcp_initialize_frames(struct thread_context *thread_context, unsigned char *frame_data,
				  size_t num_frames, const unsigned char *source)
{
	const struct traffic_class_config *dcp_config = thread_context->conf;
	size_t i;

	for (i = 0; i < num_frames; ++i)
		initialize_profinet_frame(
			SECURITY_MODE_NONE, frame_idx(frame_data, i), MAX_FRAME_SIZE, source,
			dcp_config->l2_destination, dcp_config->payload_pattern,
			dcp_config->payload_pattern_length,
			dcp_config->vid | dcp_config->pcp << VLAN_PCP_SHIFT, DCP_FRAMEID);
}

static void dcp_build_frame_from_rx(struct thread_context *thread_context,
				    const unsigned char *old_frame, size_t old_frame_len,
				    unsigned char *new_frame, size_t new_frame_len,
				    const unsigned char *source)
{
	const struct traffic_class_config *dcp_config = thread_context->conf;
	struct vlan_ethernet_header *eth_new, *eth_old;
	struct profinet_rt_header *rt;

	/*
	 * Three tasks:
	 *  -> Keep destination and adjust source
	 *  -> Set new Tx Timestamp
	 *  -> Inject VLAN header
	 */

	if (new_frame_len < old_frame_len + sizeof(struct vlan_header))
		return;

	/* Copy payload */
	memcpy(new_frame + ETH_ALEN * 2 + sizeof(struct vlan_header), old_frame + ETH_ALEN * 2,
	       old_frame_len - ETH_ALEN * 2);

	/* Swap source destination */
	eth_new = (struct vlan_ethernet_header *)new_frame;
	eth_old = (struct vlan_ethernet_header *)old_frame;

	memcpy(eth_new->destination, eth_old->destination, ETH_ALEN);
	memcpy(eth_new->source, source, ETH_ALEN);

	/* Inject VLAN info */
	eth_new->vlan_proto = htons(ETH_P_8021Q);
	eth_new->vlantci = htons(dcp_config->vid | dcp_config->pcp << VLAN_PCP_SHIFT);
	eth_new->vlan_encapsulated_proto = htons(ETH_P_PROFINET_RT);

	rt = (struct profinet_rt_header *)(new_frame + sizeof(*eth_new));
	set_mirror_tx_timestamp(&rt->meta_data);
}

static int dcp_send_messages(struct thread_context *thread_context, int socket_fd,
			     struct sockaddr_ll *destination, unsigned char *frame_data,
			     size_t num_frames)
{
	const struct traffic_class_config *dcp_config = thread_context->conf;
	struct packet_send_request send_req = {
		.traffic_class = stat_frame_type_to_string(DCP_FRAME_TYPE),
		.socket_fd = socket_fd,
		.destination = destination,
		.frame_data = frame_data,
		.num_frames = num_frames,
		.frame_length = dcp_config->frame_length,
		.duration = 0,
		.tx_time_offset = 0,
		.meta_data_offset = thread_context->meta_data_offset,
		.mirror_enabled = dcp_config->rx_mirror_enabled,
		.tx_time_enabled = false,
	};

	return packet_send_messages(thread_context->packet_context, &send_req);
}

static int dcp_send_frames(struct thread_context *thread_context, unsigned char *frame_data,
			   size_t num_frames, int socket_fd, struct sockaddr_ll *destination)
{
	const struct traffic_class_config *dcp_config = thread_context->conf;
	int len, i;

	/* Send them */
	len = dcp_send_messages(thread_context, socket_fd, destination, frame_data, num_frames);

	for (i = 0; i < len; i++) {
		uint64_t sequence_counter;

		sequence_counter = get_sequence_counter(frame_data + i * dcp_config->frame_length,
							thread_context->meta_data_offset,
							dcp_config->num_frames_per_cycle);

		stat_frame_sent(DCP_FRAME_TYPE, sequence_counter);
	}

	return len;
}

static void dcp_gen_and_send_frames(struct thread_context *thread_context, int socket_fd,
				    struct sockaddr_ll *destination,
				    uint64_t sequence_counter_begin)
{
	const struct traffic_class_config *dcp_config = thread_context->conf;
	struct vlan_ethernet_header *eth;
	struct profinet_rt_header *rt;
	struct timespec tx_time = {};
	int len, i;

	clock_gettime(app_config.application_clock_id, &tx_time);

	/* Adjust meta data */
	for (i = 0; i < dcp_config->num_frames_per_cycle; i++) {
		rt = (struct profinet_rt_header *)(frame_idx(thread_context->tx_frame_data, i) +
						   sizeof(*eth));
		sequence_counter_to_meta_data(&rt->meta_data, sequence_counter_begin + i,
					      dcp_config->num_frames_per_cycle);

		tx_timestamp_to_meta_data(&rt->meta_data, ts_to_ns(&tx_time));
	}

	/* Send them */
	len = dcp_send_messages(thread_context, socket_fd, destination,
				thread_context->tx_frame_data, dcp_config->num_frames_per_cycle);

	for (i = 0; i < len; i++)
		stat_frame_sent(DCP_FRAME_TYPE, sequence_counter_begin + i);
}

static void *dcp_tx_thread_routine(void *data)
{
	struct thread_context *thread_context = data;
	const struct traffic_class_config *dcp_config = thread_context->conf;
	size_t received_frames_length = MAX_FRAME_SIZE * dcp_config->num_frames_per_cycle;
	unsigned char *received_frames = thread_context->rx_frame_data;
	const bool mirror_enabled = dcp_config->rx_mirror_enabled;
	pthread_cond_t *cond = &thread_context->data_cond_var;
	pthread_mutex_t *mutex = &thread_context->data_mutex;
	struct sockaddr_ll destination;
	uint64_t sequence_counter = 0;
	unsigned int if_index;
	int socket_fd;

	socket_fd = thread_context->socket_fd;

	if_index = if_nametoindex(dcp_config->interface);
	if (!if_index) {
		log_message(LOG_LEVEL_ERROR, "DcpTx: if_nametoindex() failed!\n");
		return NULL;
	}

	memset(&destination, '\0', sizeof(destination));
	destination.sll_family = PF_PACKET;
	destination.sll_ifindex = if_index;
	destination.sll_halen = ETH_ALEN;
	memcpy(destination.sll_addr, dcp_config->l2_destination, ETH_ALEN);

	dcp_initialize_frames(thread_context, thread_context->tx_frame_data,
			      dcp_config->num_frames_per_cycle, thread_context->source);

	while (!thread_context->stop) {
		struct timespec timeout;
		size_t num_frames;
		int ret;

		/*
		 * Wait until signalled. These DCP frames have to be sent after the RTA
		 * frames. Therefore, the RTA TxThread signals this one here.
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
		 * Send DcpFrames, two possibilites:
		 *  a) Generate it, or
		 *  b) Use received ones if mirror enabled
		 */
		if (!mirror_enabled) {
			if (num_frames) {
				dcp_gen_and_send_frames(thread_context, socket_fd, &destination,
							sequence_counter);

				sequence_counter += num_frames;
			}
		} else {
			size_t len;

			ring_buffer_fetch(thread_context->mirror_buffer, received_frames,
					  received_frames_length, &len);

			/* Len should be a multiple of frame size */
			num_frames = len / dcp_config->frame_length;
			dcp_send_frames(thread_context, received_frames, num_frames, socket_fd,
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

static int dcp_rx_frame(void *data, unsigned char *frame_data, size_t len)
{
	struct thread_context *thread_context = data;
	const struct traffic_class_config *dcp_config = thread_context->conf;
	const unsigned char *expected_pattern = (const unsigned char *)dcp_config->payload_pattern;
	const size_t expected_pattern_length = dcp_config->payload_pattern_length;
	const size_t num_frames_per_cycle = dcp_config->num_frames_per_cycle;
	const bool mirror_enabled = dcp_config->rx_mirror_enabled;
	const bool ignore_rx_errors = dcp_config->ignore_rx_errors;
	const size_t frame_length = dcp_config->frame_length;
	bool out_of_order, payload_mismatch, frame_id_mismatch;
	unsigned char new_frame[MAX_FRAME_SIZE];
	struct profinet_rt_header *rt;
	uint64_t sequence_counter;
	uint64_t tx_timestamp;

	if (len != frame_length - 4) {
		log_message(LOG_LEVEL_ERROR, "DcpRx: Frame with wrong length received!\n");
		return -EINVAL;
	}

	/*
	 * Check cycle counter and payload. The frame id range is checked by the attached BPF
	 * filter.
	 */
	rt = (struct profinet_rt_header *)(frame_data + sizeof(struct ethhdr));
	sequence_counter = meta_data_to_sequence_counter(&rt->meta_data, num_frames_per_cycle);

	tx_timestamp = meta_data_to_tx_timestamp(&rt->meta_data);

	out_of_order = sequence_counter != thread_context->rx_sequence_counter;
	payload_mismatch = memcmp(frame_data + sizeof(struct ethhdr) + sizeof(*rt),
				  expected_pattern, expected_pattern_length);
	frame_id_mismatch = false;

	stat_frame_received(DCP_FRAME_TYPE, sequence_counter, out_of_order, payload_mismatch,
			    frame_id_mismatch, tx_timestamp, 0, 0);

	if (out_of_order) {
		if (!ignore_rx_errors)
			log_message(LOG_LEVEL_WARNING,
				    "DcpRx: frame[%" PRIu64 "] SequenceCounter mismatch: %" PRIu64
				    "!\n",
				    sequence_counter, thread_context->rx_sequence_counter);
		thread_context->rx_sequence_counter++;
	}

	if (payload_mismatch)
		log_message(LOG_LEVEL_WARNING,
			    "DcpRx: frame[%" PRIu64 "] Payload Pattern mismatch!\n",
			    sequence_counter);

	thread_context->rx_sequence_counter++;

	/* If mirror enabled, assemble and store the frame for Tx later. */
	if (!mirror_enabled)
		return 0;

	/* Build new frame for Tx with VLAN info. */
	dcp_build_frame_from_rx(thread_context, frame_data, len, new_frame, sizeof(new_frame),
				thread_context->source);

	/* Store the new frame. */
	ring_buffer_add(thread_context->mirror_buffer, new_frame, len + sizeof(struct vlan_header));

	pthread_mutex_lock(&thread_context->data_mutex);
	thread_context->num_frames_available++;
	pthread_mutex_unlock(&thread_context->data_mutex);

	return 0;
}

static void *dcp_rx_thread_routine(void *data)
{
	struct thread_context *thread_context = data;
	const uint64_t cycle_time_ns = app_config.application_base_cycle_time_ns;
	struct timespec wakeup_time;
	int socket_fd, ret;

	socket_fd = thread_context->socket_fd;

	ret = get_thread_start_time(app_config.application_rx_base_offset_ns, &wakeup_time);
	if (ret) {
		log_message(LOG_LEVEL_ERROR, "DcpRx: Failed to calculate thread start time: %s!\n",
			    strerror(errno));
		return NULL;
	}

	while (!thread_context->stop) {
		struct packet_receive_request recv_req = {
			.traffic_class = thread_context->traffic_class,
			.socket_fd = socket_fd,
			.receive_function = dcp_rx_frame,
			.data = thread_context,
		};

		/* Wait until next period. */
		increment_period(&wakeup_time, cycle_time_ns);

		do {
			ret = clock_nanosleep(app_config.application_clock_id, TIMER_ABSTIME,
					      &wakeup_time, NULL);
		} while (ret == EINTR);

		if (ret) {
			log_message(LOG_LEVEL_ERROR, "DcpRx: clock_nanosleep() failed: %s\n",
				    strerror(ret));
			return NULL;
		}

		/* Receive Dcp frames. */
		packet_receive_messages(thread_context->packet_context, &recv_req);
	}

	return NULL;
}

static void *dcp_tx_generation_thread_routine(void *data)
{
	struct thread_context *thread_context = data;
	const struct traffic_class_config *dcp_config = thread_context->conf;
	uint64_t num_frames = dcp_config->num_frames_per_cycle;
	pthread_mutex_t *mutex = &thread_context->data_mutex;
	uint64_t cycle_time_ns = dcp_config->burst_period_ns;
	struct timespec wakeup_time;
	int ret;

	/*
	 * The DCP frames are generated by bursts with a certain period. This thread is responsible
	 * for generating it.
	 */

	ret = get_thread_start_time(0, &wakeup_time);
	if (ret) {
		log_message(LOG_LEVEL_ERROR,
			    "DcpTxGen: Failed to calculate thread start time: %s!\n",
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
			log_message(LOG_LEVEL_ERROR, "DcpTxGen: clock_nanosleep() failed: %s\n",
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

int dcp_threads_create(struct thread_context *thread_context)
{
	struct traffic_class_config *dcp_config;
	int ret;

	if (!config_is_traffic_class_active("Dcp"))
		goto out;

	thread_context->conf = dcp_config = &app_config.classes[DCP_FRAME_TYPE];
	thread_context->frame_type = DCP_FRAME_TYPE;
	thread_context->traffic_class = stat_frame_type_to_string(DCP_FRAME_TYPE);
	thread_context->frame_id = DCP_FRAME_TYPE;

	thread_context->socket_fd = create_dcp_socket();
	if (thread_context->socket_fd < 0) {
		fprintf(stderr, "Failed to create DcpSocket!\n");
		ret = -ENOMEM;
		goto err;
	}

	init_mutex(&thread_context->data_mutex);
	init_condition_variable(&thread_context->data_cond_var);

	thread_context->packet_context = packet_init(dcp_config->num_frames_per_cycle);
	if (!thread_context->packet_context) {
		fprintf(stderr, "Failed to allocate Dcp packet context!\n");
		ret = -ENOMEM;
		goto err_packet;
	}

	thread_context->tx_frame_data = calloc(dcp_config->num_frames_per_cycle, MAX_FRAME_SIZE);
	if (!thread_context->tx_frame_data) {
		fprintf(stderr, "Failed to allocate DcpTxFrameData!\n");
		ret = -ENOMEM;
		goto err_tx;
	}

	thread_context->rx_frame_data = calloc(dcp_config->num_frames_per_cycle, MAX_FRAME_SIZE);
	if (!thread_context->rx_frame_data) {
		fprintf(stderr, "Failed to allocate DcpRxFrameData!\n");
		ret = -ENOMEM;
		goto err_rx;
	}

	ret = get_interface_mac_address(dcp_config->interface, thread_context->source,
					sizeof(thread_context->source));
	if (ret < 0) {
		fprintf(stderr, "Failed to get Dcp Source MAC address!\n");
		goto err_mac;
	}

	if (dcp_config->rx_mirror_enabled) {
		/* Per period the expectation is: DcpNumFramesPerCycle * MAX_FRAME */
		thread_context->mirror_buffer =
			ring_buffer_allocate(MAX_FRAME_SIZE * dcp_config->num_frames_per_cycle);
		if (!thread_context->mirror_buffer) {
			fprintf(stderr, "Failed to allocate Dcp Mirror RingBuffer!\n");
			ret = -ENOMEM;
			goto err_mac;
		}
	}

	ret = create_rt_thread(&thread_context->tx_task_id, "DcpTxThread",
			       dcp_config->tx_thread_priority, dcp_config->tx_thread_cpu,
			       dcp_tx_thread_routine, thread_context);
	if (ret) {
		fprintf(stderr, "Failed to create Dcp Tx Thread!\n");
		goto err_thread;
	}

	if (!dcp_config->rx_mirror_enabled) {
		ret = create_rt_thread(&thread_context->tx_gen_task_id, "DcpTxGenThread",
				       dcp_config->tx_thread_priority, dcp_config->tx_thread_cpu,
				       dcp_tx_generation_thread_routine, thread_context);
		if (ret) {
			fprintf(stderr, "Failed to create Dcp TxGen Thread!\n");
			goto err_thread_txgen;
		}
	}

	ret = create_rt_thread(&thread_context->rx_task_id, "DcpRxThread",
			       dcp_config->rx_thread_priority, dcp_config->rx_thread_cpu,
			       dcp_rx_thread_routine, thread_context);
	if (ret) {
		fprintf(stderr, "Failed to create Dcp Rx Thread!\n");
		goto err_thread_rx;
	}

	thread_context->meta_data_offset = get_meta_data_offset(DCP_FRAME_TYPE, SECURITY_MODE_NONE);

out:
	return 0;

err_thread_rx:
	thread_context->stop = 1;
	if (thread_context->tx_gen_task_id)
		pthread_join(thread_context->tx_gen_task_id, NULL);
err_thread_txgen:
	thread_context->stop = 1;
	pthread_join(thread_context->tx_task_id, NULL);
err_thread:
	ring_buffer_free(thread_context->mirror_buffer);
err_mac:
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

void dcp_threads_free(struct thread_context *thread_context)
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

void dcp_threads_wait_for_finish(struct thread_context *thread_context)
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
