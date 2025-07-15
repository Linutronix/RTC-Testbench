// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2020-2024 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_vlan.h>

#include "config.h"
#include "log.h"
#include "net.h"
#include "net_def.h"
#include "stat.h"
#include "thread.h"
#include "udp_thread.h"
#include "utils.h"

static void udp_initialize_frame(struct thread_context *thread_context, unsigned char *frame_data)
{
	const struct traffic_class_config *udp_config = thread_context->conf;
	struct reference_meta_data *meta;

	/*
	 * UdpFrame:
	 *   Cycle counter
	 *   Payload
	 *   Padding to maxFrame
	 */

	/* Payload: SequenceCounter + Data */
	meta = (struct reference_meta_data *)frame_data;
	memset(meta, '\0', sizeof(*meta));
	memcpy(frame_data + sizeof(*meta), udp_config->payload_pattern,
	       udp_config->payload_pattern_length);

	/* Padding: '\0' */
}

static void udp_send_frame(struct thread_context *thread_context, const unsigned char *frame_data,
			   size_t frame_length, size_t num_frames_per_cycle, int socket_fd,
			   const struct sockaddr_storage *destination)
{
	struct reference_meta_data *meta;
	struct timespec tx_time = {};
	uint64_t sequence_counter;
	ssize_t ret = -1;

	clock_gettime(app_config.application_clock_id, &tx_time);

	/* Fetch meta data */
	meta = (struct reference_meta_data *)frame_data;
	sequence_counter = meta_data_to_sequence_counter(meta, num_frames_per_cycle);

	tx_timestamp_to_meta_data(meta, ts_to_ns(&tx_time));

	/* Send it */
	switch (destination->ss_family) {
	case AF_INET:
		ret = sendto(socket_fd, frame_data, frame_length, 0,
			     (struct sockaddr_in *)destination, sizeof(struct sockaddr_in));
		break;
	case AF_INET6:
		ret = sendto(socket_fd, frame_data, frame_length, 0,
			     (struct sockaddr_in6 *)destination, sizeof(struct sockaddr_in6));
		break;
	}
	if (ret < 0) {
		log_message(LOG_LEVEL_ERROR, "%sTx: send() for %" PRIu64 " failed: %s\n",
			    thread_context->traffic_class, sequence_counter, strerror(errno));
		return;
	}

	stat_frame_sent(thread_context->frame_type, sequence_counter);
}

static void udp_gen_and_send_frame(struct thread_context *thread_context, unsigned char *frame_data,
				   size_t frame_length, size_t num_frames_per_cycle, int socket_fd,
				   uint64_t sequence_counter,
				   const struct sockaddr_storage *destination)
{
	struct reference_meta_data *meta;
	struct timespec tx_time = {};
	ssize_t ret = -1;

	clock_gettime(app_config.application_clock_id, &tx_time);

	/* Adjust meta data */
	meta = (struct reference_meta_data *)frame_data;
	sequence_counter_to_meta_data(meta, sequence_counter, num_frames_per_cycle);

	tx_timestamp_to_meta_data(meta, ts_to_ns(&tx_time));

	/* Send it */
	switch (destination->ss_family) {
	case AF_INET:
		ret = sendto(socket_fd, frame_data, frame_length, 0,
			     (struct sockaddr_in *)destination, sizeof(struct sockaddr_in));
		break;
	case AF_INET6:
		ret = sendto(socket_fd, frame_data, frame_length, 0,
			     (struct sockaddr_in6 *)destination, sizeof(struct sockaddr_in6));
		break;
	default:
		ret = -EINVAL;
	}
	if (ret < 0) {
		log_message(LOG_LEVEL_ERROR, "%sTx: send() for %" PRIu64 " failed: %s\n",
			    thread_context->traffic_class, sequence_counter, strerror(errno));
		return;
	}

	stat_frame_sent(thread_context->frame_type, sequence_counter);
}

static void *udp_tx_thread_routine(void *data)
{
	struct thread_context *thread_context = data;
	const struct traffic_class_config *udp_config = thread_context->conf;
	size_t received_frames_length = MAX_FRAME_SIZE * udp_config->num_frames_per_cycle;
	unsigned char *received_frames = thread_context->rx_frame_data;
	const bool mirror_enabled = udp_config->rx_mirror_enabled;
	pthread_mutex_t *mutex = &thread_context->data_mutex;
	pthread_cond_t *cond = &thread_context->data_cond_var;
	uint64_t sequence_counter = 0;
	unsigned char *frame;
	int socket_fd;

	socket_fd = thread_context->socket_fd;
	frame = thread_context->tx_frame_data;

	udp_initialize_frame(thread_context, frame);

	while (!thread_context->stop) {
		struct timespec timeout;
		size_t num_frames, i;
		int ret;

		/*
		 * Wait until signalled. These UDP frames have to be sent after the LLDP
		 * frames. Therefore, the LLDP or UDP High TxThread signals this one here.
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
		 * Send UdpFrames, two possibilites:
		 *  a) Generate it, or
		 *  b) Use received ones if mirror enabled
		 */
		if (!mirror_enabled) {
			/* Send UdpFrames */
			for (i = 0; i < num_frames; ++i)
				udp_gen_and_send_frame(
					thread_context, frame, udp_config->frame_length,
					udp_config->num_frames_per_cycle, socket_fd,
					sequence_counter++, &thread_context->destination);
		} else {
			size_t len;

			ring_buffer_fetch(thread_context->mirror_buffer, received_frames,
					  received_frames_length, &len);

			/* Len should be a multiple of frame size */
			for (i = 0; i < len / udp_config->frame_length; ++i)
				udp_send_frame(thread_context,
					       received_frames + i * udp_config->frame_length,
					       udp_config->frame_length,
					       udp_config->num_frames_per_cycle, socket_fd,
					       &thread_context->destination);

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

static void *udp_rx_thread_routine(void *data)
{
	struct thread_context *thread_context = data;
	const struct traffic_class_config *udp_config = thread_context->conf;
	const unsigned char *expected_pattern = (const unsigned char *)udp_config->payload_pattern;
	const size_t expected_pattern_length = udp_config->payload_pattern_length;
	const uint64_t cycle_time_ns = app_config.application_base_cycle_time_ns;
	const size_t num_frames_per_cycle = udp_config->num_frames_per_cycle;
	const bool mirror_enabled = udp_config->rx_mirror_enabled;
	const bool ignore_rx_errors = udp_config->ignore_rx_errors;
	const ssize_t frame_length = udp_config->frame_length;
	unsigned char frame[MAX_FRAME_SIZE];
	uint64_t sequence_counter = 0;
	struct timespec wakeup_time;
	uint64_t tx_timestamp;
	int socket_fd, ret;

	socket_fd = thread_context->socket_fd;

	ret = get_thread_start_time(app_config.application_rx_base_offset_ns, &wakeup_time);
	if (ret) {
		log_message(LOG_LEVEL_ERROR, "%sRx: Failed to calculate thread start time: %s!\n",
			    thread_context->traffic_class, strerror(errno));
		return NULL;
	}

	while (!thread_context->stop) {
		/* Wait until next period. */
		increment_period(&wakeup_time, cycle_time_ns);

		do {
			ret = clock_nanosleep(app_config.application_clock_id, TIMER_ABSTIME,
					      &wakeup_time, NULL);
		} while (ret == EINTR);

		if (ret) {
			log_message(LOG_LEVEL_ERROR, "%sRx: clock_nanosleep() failed: %s\n",
				    thread_context->traffic_class, strerror(ret));
			return NULL;
		}

		/* Receive Udp packets. */
		while (true) {
			bool out_of_order, payload_mismatch, frame_id_mismatch;
			struct reference_meta_data *meta;
			uint64_t rx_sequence_counter;
			ssize_t len;

			len = recv(socket_fd, frame, sizeof(frame), 0);
			if (len == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
				log_message(LOG_LEVEL_ERROR, "%sRx: recv() failed: %s\n",
					    thread_context->traffic_class, strerror(errno));
				continue;
			}
			if (len == 0)
				continue;

			/* No more frames. Comeback within next period. */
			if (len == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
				break;

			/* Process received packet. */
			if (len != frame_length) {
				log_message(LOG_LEVEL_WARNING,
					    "%sRx: Frame with wrong length received!\n",
					    thread_context->traffic_class);
				continue;
			}

			/*
			 * Check cycle counter and payload. The ether type is checked by the
			 * attached BPF filter.
			 */
			meta = (struct reference_meta_data *)frame;
			rx_sequence_counter =
				meta_data_to_sequence_counter(meta, num_frames_per_cycle);

			tx_timestamp = meta_data_to_tx_timestamp(meta);
			set_mirror_tx_timestamp(meta);

			out_of_order = sequence_counter != rx_sequence_counter;
			payload_mismatch = memcmp(frame + sizeof(struct reference_meta_data),
						  expected_pattern, expected_pattern_length);
			frame_id_mismatch = false;

			stat_frame_received(thread_context->frame_type, sequence_counter,
					    out_of_order, payload_mismatch, frame_id_mismatch,
					    tx_timestamp, 0, 0);

			if (out_of_order) {
				if (!ignore_rx_errors)
					log_message(LOG_LEVEL_WARNING,
						    "%sRx: frame[%" PRIu64
						    "] SequenceCounter mismatch: %" PRIu64 "!\n",
						    thread_context->traffic_class,
						    rx_sequence_counter, sequence_counter);
				sequence_counter++;
			}

			sequence_counter++;

			if (payload_mismatch)
				log_message(LOG_LEVEL_WARNING,
					    "%sRx: frame[%" PRIu64 "] Payload Pattern mismatch!\n",
					    thread_context->traffic_class, rx_sequence_counter);

			/* If mirror enabled, assemble and store the frame for Tx later. */
			if (!mirror_enabled)
				continue;

			/* Store the new frame. */
			ring_buffer_add(thread_context->mirror_buffer, frame, len);

			pthread_mutex_lock(&thread_context->data_mutex);
			thread_context->num_frames_available++;
			pthread_mutex_unlock(&thread_context->data_mutex);
		}
	}

	return NULL;
}

static void *udp_tx_generation_thread_routine(void *data)
{
	struct thread_context *thread_context = data;
	const struct traffic_class_config *udp_config = thread_context->conf;
	pthread_mutex_t *mutex = &thread_context->data_mutex;
	uint64_t cycle_time_ns = udp_config->burst_period_ns;
	uint64_t num_frames = udp_config->num_frames_per_cycle;
	struct timespec wakeup_time;
	int ret;

	/*
	 * The UDP frames are generated by bursts with a certain period. This thread is responsible
	 * for generating it.
	 */

	ret = get_thread_start_time(0, &wakeup_time);
	if (ret) {
		log_message(LOG_LEVEL_ERROR,
			    "%sTxGen: Failed to calculate thread start time: %s!\n",
			    thread_context->traffic_class, strerror(errno));
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
			log_message(LOG_LEVEL_ERROR, "%sTxGen: clock_nanosleep() failed: %s\n",
				    thread_context->traffic_class, strerror(ret));
			return NULL;
		}

		/* Generate frames */
		pthread_mutex_lock(mutex);
		thread_context->num_frames_available = num_frames;
		pthread_mutex_unlock(mutex);
	}

	return NULL;
}

static int udp_threads_create(struct thread_context *thread_context)
{
	const struct traffic_class_config *udp_config = thread_context->conf;
	char thread_name[128];
	int ret;

	if (thread_context->frame_type == UDP_HIGH_FRAME_TYPE &&
	    !config_is_traffic_class_active("UdpHigh")) {
		ret = 0;
		goto out;
	}
	if (thread_context->frame_type == UDP_LOW_FRAME_TYPE &&
	    !config_is_traffic_class_active("UdpLow")) {
		ret = 0;
		goto out;
	}

	thread_context->socket_fd = create_udp_socket(
		udp_config->l3_destination, udp_config->l3_source, udp_config->l3_port,
		udp_config->socket_priority, &thread_context->destination);
	if (thread_context->socket_fd < 0) {
		fprintf(stderr, "Failed to create UdpSocket!\n");
		ret = -errno;
		goto err;
	}

	init_mutex(&thread_context->data_mutex);
	init_condition_variable(&thread_context->data_cond_var);

	thread_context->tx_frame_data = calloc(1, MAX_FRAME_SIZE);
	if (!thread_context->tx_frame_data) {
		fprintf(stderr, "Failed to allocate UdpTxFrameData!\n");
		ret = -ENOMEM;
		goto err_tx;
	}

	thread_context->rx_frame_data = calloc(udp_config->num_frames_per_cycle, MAX_FRAME_SIZE);
	if (!thread_context->rx_frame_data) {
		fprintf(stderr, "Failed to allocate UdpRxFrameData!\n");
		ret = -ENOMEM;
		goto err_rx;
	}

	if (udp_config->rx_mirror_enabled) {
		/* Per period the expectation is: UdpNumFramesPerCycle * MAX_FRAME */
		thread_context->mirror_buffer =
			ring_buffer_allocate(MAX_FRAME_SIZE * udp_config->num_frames_per_cycle);
		if (!thread_context->mirror_buffer) {
			fprintf(stderr, "Failed to allocate Udp Mirror RingBuffer!\n");
			ret = -ENOMEM;
			goto err_buffer;
		}
	}

	snprintf(thread_name, sizeof(thread_name), "%sTxThread", thread_context->traffic_class);

	ret = create_rt_thread(&thread_context->tx_task_id, thread_name,
			       udp_config->tx_thread_priority, udp_config->tx_thread_cpu,
			       udp_tx_thread_routine, thread_context);
	if (ret) {
		fprintf(stderr, "Failed to create Udp Tx Thread!\n");
		goto err_thread;
	}

	snprintf(thread_name, sizeof(thread_name), "%sTxGenThread", thread_context->traffic_class);

	if (!udp_config->rx_mirror_enabled) {
		ret = create_rt_thread(&thread_context->tx_gen_task_id, "UdpLowTxGenThread",
				       udp_config->tx_thread_priority, udp_config->tx_thread_cpu,
				       udp_tx_generation_thread_routine, thread_context);
		if (ret) {
			fprintf(stderr, "Failed to create Udp TxGen Thread!\n");
			goto err_thread_txgen;
		}
	}

	snprintf(thread_name, sizeof(thread_name), "%sRxThread", thread_context->traffic_class);

	ret = create_rt_thread(&thread_context->rx_task_id, thread_name,
			       udp_config->rx_thread_priority, udp_config->rx_thread_cpu,
			       udp_rx_thread_routine, thread_context);
	if (ret) {
		fprintf(stderr, "Failed to create Udp Rx Thread!\n");
		goto err_thread_rx;
	}

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
err_buffer:
	free(thread_context->rx_frame_data);
err_rx:
	free(thread_context->tx_frame_data);
err_tx:
	close(thread_context->socket_fd);
err:
out:
	return ret;
}

static void udp_threads_free(struct thread_context *thread_context)
{
	if (!thread_context)
		return;

	ring_buffer_free(thread_context->mirror_buffer);

	free(thread_context->tx_frame_data);
	free(thread_context->rx_frame_data);

	if (thread_context->socket_fd > 0)
		close(thread_context->socket_fd);
}

static void udp_threads_wait_for_finish(struct thread_context *thread_context)
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

int udp_low_threads_create(struct thread_context *udp_thread_context)
{
	udp_thread_context->conf = &app_config.classes[UDP_LOW_FRAME_TYPE];
	udp_thread_context->frame_type = UDP_LOW_FRAME_TYPE;
	udp_thread_context->traffic_class = stat_frame_type_to_string(UDP_LOW_FRAME_TYPE);

	return udp_threads_create(udp_thread_context);
}

void udp_low_threads_free(struct thread_context *thread_context)
{
	udp_threads_free(thread_context);
}

void udp_low_threads_wait_for_finish(struct thread_context *thread_context)
{
	udp_threads_wait_for_finish(thread_context);
}

int udp_high_threads_create(struct thread_context *udp_thread_context)
{
	udp_thread_context->conf = &app_config.classes[UDP_HIGH_FRAME_TYPE];
	udp_thread_context->frame_type = UDP_HIGH_FRAME_TYPE;
	udp_thread_context->traffic_class = stat_frame_type_to_string(UDP_HIGH_FRAME_TYPE);

	return udp_threads_create(udp_thread_context);
}

void udp_high_threads_free(struct thread_context *thread_context)
{
	udp_threads_free(thread_context);
}

void udp_high_threads_wait_for_finish(struct thread_context *thread_context)
{
	udp_threads_wait_for_finish(thread_context);
}
