// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2020-2025 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
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
#include "log.h"
#include "net.h"
#include "packet.h"
#include "profinet.h"
#include "rtc_thread.h"
#include "security.h"
#include "stat.h"
#include "thread.h"
#include "utils.h"
#include "xdp.h"

static void rtc_initialize_frames(struct thread_context *thread_context, unsigned char *frame_data,
				  size_t num_frames, const unsigned char *source,
				  const unsigned char *destination)
{
	const struct traffic_class_config *rtc_config = thread_context->conf;
	size_t i;

	for (i = 0; i < num_frames; ++i) {
		unsigned char *frame = frame_idx(frame_data, i);
		size_t frame_length = MAX_FRAME_SIZE;

		/*
		 * In case both AF_XDP and Tx HW Timestamp are enabled the payload starts at:
		 *   frame_data + sizeof(struct xsk_tx_metadata)
		 */
#ifdef TX_TIMESTAMP
		if (rtc_config->xdp_enabled && rtc_config->tx_hwtstamp_enabled) {
			frame += sizeof(struct xsk_tx_metadata);
			frame_length -= sizeof(struct xsk_tx_metadata);
		}
#endif

		initialize_profinet_frame(rtc_config->security_mode, frame, frame_length, source,
					  destination, rtc_config->payload_pattern,
					  rtc_config->payload_pattern_length,
					  rtc_config->vid | rtc_config->pcp << VLAN_PCP_SHIFT,
					  thread_context->frame_id);
	}
}

static int rtc_send_messages(struct thread_context *thread_context, int socket_fd,
			     struct sockaddr_ll *destination, unsigned char *frame_data,
			     size_t num_frames)
{
	const struct traffic_class_config *rtc_config = thread_context->conf;
	struct packet_send_request send_req = {
		.traffic_class = stat_frame_type_to_string(RTC_FRAME_TYPE),
		.socket_fd = socket_fd,
		.destination = destination,
		.frame_data = frame_data,
		.num_frames = num_frames,
		.frame_length = rtc_config->frame_length,
		.duration = 0,
		.tx_time_offset = 0,
		.meta_data_offset = thread_context->meta_data_offset,
		.mirror_enabled = rtc_config->rx_mirror_enabled,
		.tx_time_enabled = false,
	};

	return packet_send_messages(thread_context->packet_context, &send_req);
}

static int rtc_send_frames(struct thread_context *thread_context, unsigned char *frame_data,
			   size_t num_frames, int socket_fd, struct sockaddr_ll *destination)
{
	const struct traffic_class_config *rtc_config = thread_context->conf;
	int len, i;

	/* Send it */
	len = rtc_send_messages(thread_context, socket_fd, destination, frame_data, num_frames);

	for (i = 0; i < len; i++) {
		uint64_t sequence_counter;

		sequence_counter = get_sequence_counter(frame_data + i * rtc_config->frame_length,
							thread_context->meta_data_offset,
							rtc_config->num_frames_per_cycle);

		stat_frame_sent(RTC_FRAME_TYPE, sequence_counter);
	}

	return len;
}

static int rtc_gen_and_send_frames(struct thread_context *thread_context, int socket_fd,
				   struct sockaddr_ll *destination, uint64_t sequence_counter_begin)
{
	const struct traffic_class_config *rtc_config = thread_context->conf;
	struct timespec tx_time = {};
	int len, i;

	clock_gettime(app_config.application_clock_id, &tx_time);

	for (i = 0; i < rtc_config->num_frames_per_cycle; i++) {
		struct prepare_frame_config frame_config;
		int err;

		frame_config.mode = rtc_config->security_mode;
		frame_config.security_context = thread_context->tx_security_context;
		frame_config.iv_prefix = (const unsigned char *)rtc_config->security_iv_prefix;
		frame_config.payload_pattern = thread_context->payload_pattern;
		frame_config.payload_pattern_length = thread_context->payload_pattern_length;
		frame_config.frame_data = frame_idx(thread_context->tx_frame_data, i);
		frame_config.frame_length = rtc_config->frame_length;
		frame_config.num_frames_per_cycle = rtc_config->num_frames_per_cycle;
		frame_config.sequence_counter = sequence_counter_begin + i;
		frame_config.tx_timestamp = ts_to_ns(&tx_time);
		frame_config.meta_data_offset = thread_context->meta_data_offset;

		err = prepare_frame_for_tx(&frame_config);
		if (err)
			log_message(LOG_LEVEL_ERROR, "RtcTx: Failed to prepare frame for Tx!\n");
	}

	/* Send it */
	len = rtc_send_messages(thread_context, socket_fd, destination,
				thread_context->tx_frame_data, rtc_config->num_frames_per_cycle);

	for (i = 0; i < len; i++)
		stat_frame_sent(RTC_FRAME_TYPE, sequence_counter_begin + i);

	return len;
}

static void rtc_gen_and_send_xdp_frames(struct thread_context *thread_context,
					struct xdp_socket *xsk, uint64_t sequence_counter,
					uint32_t *frame_number)
{
	const struct traffic_class_config *rtc_config = thread_context->conf;
	struct xdp_gen_config xdp;

	xdp.mode = rtc_config->security_mode;
	xdp.security_context = thread_context->tx_security_context;
	xdp.iv_prefix = (const unsigned char *)rtc_config->security_iv_prefix;
	xdp.payload_pattern = thread_context->payload_pattern;
	xdp.payload_pattern_length = thread_context->payload_pattern_length;
	xdp.frame_length = rtc_config->frame_length;
	xdp.num_frames_per_cycle = rtc_config->num_frames_per_cycle;
	xdp.frame_number = frame_number;
	xdp.sequence_counter_begin = sequence_counter;
	xdp.meta_data_offset = thread_context->meta_data_offset;
	xdp.frame_type = RTC_FRAME_TYPE;
	xdp.tx_time = NULL;

	xdp_gen_and_send_frames(xsk, &xdp);
}

static void *rtc_tx_thread_routine(void *data)
{
	struct thread_context *thread_context = data;
	const struct traffic_class_config *rtc_config = thread_context->conf;
	size_t received_frames_length = MAX_FRAME_SIZE * rtc_config->num_frames_per_cycle;
	struct security_context *security_context = thread_context->tx_security_context;
	const uint64_t cycle_time_ns = app_config.application_base_cycle_time_ns;
	unsigned char *received_frames = thread_context->rx_frame_data;
	const bool mirror_enabled = rtc_config->rx_mirror_enabled;
	struct sockaddr_ll destination;
	unsigned char source[ETH_ALEN];
	uint64_t sequence_counter = 0;
	struct timespec wakeup_time;
	unsigned int if_index;
	int ret, socket_fd;

	socket_fd = thread_context->socket_fd;

	ret = get_interface_mac_address(rtc_config->interface, source, ETH_ALEN);
	if (ret < 0) {
		log_message(LOG_LEVEL_ERROR, "RtcTx: Failed to get Source MAC address!\n");
		return NULL;
	}

	if_index = if_nametoindex(rtc_config->interface);
	if (!if_index) {
		log_message(LOG_LEVEL_ERROR, "RtcTx: if_nametoindex() failed!\n");
		return NULL;
	}

	memset(&destination, '\0', sizeof(destination));
	destination.sll_family = PF_PACKET;
	destination.sll_ifindex = if_index;
	destination.sll_halen = ETH_ALEN;
	memcpy(destination.sll_addr, rtc_config->l2_destination, ETH_ALEN);

	rtc_initialize_frames(thread_context, thread_context->tx_frame_data,
			      rtc_config->num_frames_per_cycle, source, rtc_config->l2_destination);

	prepare_openssl(security_context);
	rtc_initialize_frames(thread_context, thread_context->frame_copy, 1, source,
			      rtc_config->l2_destination);

	ret = get_thread_start_time(app_config.application_tx_base_offset_ns, &wakeup_time);
	if (ret) {
		log_message(LOG_LEVEL_ERROR, "RtcTx: Failed to calculate thread start time: %s!\n",
			    strerror(errno));
		return NULL;
	}

	while (!thread_context->stop) {
		if (!thread_context->is_first) {
			struct timespec timeout;

			/*
			 * Wait until signalled. These RTC frames have to be sent after the TSN Low
			 * frames.
			 */
			clock_gettime(CLOCK_MONOTONIC, &timeout);
			timeout.tv_sec++;

			pthread_mutex_lock(&thread_context->data_mutex);
			ret = pthread_cond_timedwait(&thread_context->data_cond_var,
						     &thread_context->data_mutex, &timeout);
			pthread_mutex_unlock(&thread_context->data_mutex);

			/* In case of shutdown a signal may be missing. */
			if (ret == ETIMEDOUT)
				continue;
		} else {
			/* Wait until next period */
			increment_period(&wakeup_time, cycle_time_ns);

			do {
				ret = clock_nanosleep(app_config.application_clock_id,
						      TIMER_ABSTIME, &wakeup_time, NULL);
			} while (ret == EINTR);

			if (ret) {
				log_message(LOG_LEVEL_ERROR,
					    "RtcTx: clock_nanosleep() failed: %s\n", strerror(ret));
				return NULL;
			}
		}

		/*
		 * Send RtcFrames, two possibilites:
		 *  a) Generate it, or
		 *  b) Use received ones if mirror enabled
		 */
		if (!mirror_enabled) {
			rtc_gen_and_send_frames(thread_context, socket_fd, &destination,
						sequence_counter);

			sequence_counter += rtc_config->num_frames_per_cycle;
		} else {
			size_t len, num_frames;

			ring_buffer_fetch(thread_context->mirror_buffer, received_frames,
					  received_frames_length, &len);

			/* Len should be a multiple of frame size */
			num_frames = len / rtc_config->frame_length;
			rtc_send_frames(thread_context, received_frames, num_frames, socket_fd,
					&destination);
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

/*
 * This Tx thread routine differs to the standard one in terms of the sending interface. This one
 * uses the AF_XDP user space interface.
 */
static void *rtc_xdp_tx_thread_routine(void *data)
{
	struct thread_context *thread_context = data;
	const struct traffic_class_config *rtc_config = thread_context->conf;
	struct security_context *security_context = thread_context->tx_security_context;
	const uint64_t cycle_time_ns = app_config.application_base_cycle_time_ns;
	const bool mirror_enabled = rtc_config->rx_mirror_enabled;
	uint32_t frame_number = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	const size_t num_frames = rtc_config->num_frames_per_cycle;
	unsigned char source[ETH_ALEN];
	uint64_t sequence_counter = 0;
	struct timespec wakeup_time;
	unsigned char *frame_data;
	struct xdp_socket *xsk;
	int ret;

	xsk = thread_context->xsk;
	xsk->tx_hwts.rtt = &round_trip_contexts[RTC_FRAME_TYPE];
	xsk->tx_hwts.frames_per_cycle = rtc_config->num_frames_per_cycle;

	ret = get_interface_mac_address(rtc_config->interface, source, ETH_ALEN);
	if (ret < 0) {
		log_message(LOG_LEVEL_ERROR, "RtcTx: Failed to get Source MAC address!\n");
		return NULL;
	}

	/* First half of umem area is for Rx, the second half is for Tx. */
	frame_data = xsk_umem__get_data(xsk->umem.buffer,
					XDP_FRAME_SIZE * XSK_RING_PROD__DEFAULT_NUM_DESCS);

	/* Initialize all Tx frames */
	rtc_initialize_frames(thread_context, frame_data, XSK_RING_CONS__DEFAULT_NUM_DESCS, source,
			      rtc_config->l2_destination);

	prepare_openssl(security_context);
	rtc_initialize_frames(thread_context, thread_context->frame_copy, 1, source,
			      rtc_config->l2_destination);

	ret = get_thread_start_time(app_config.application_tx_base_offset_ns, &wakeup_time);
	if (ret) {
		log_message(LOG_LEVEL_ERROR, "RtcTx: Failed to calculate thread start time: %s!\n",
			    strerror(errno));
		return NULL;
	}

	while (!thread_context->stop) {
		if (!thread_context->is_first) {
			struct timespec timeout;

			/*
			 * Wait until signalled. These RTC frames have to be sent after the TSN Low
			 * frames.
			 */
			clock_gettime(CLOCK_MONOTONIC, &timeout);
			timeout.tv_sec++;

			pthread_mutex_lock(&thread_context->data_mutex);
			ret = pthread_cond_timedwait(&thread_context->data_cond_var,
						     &thread_context->data_mutex, &timeout);
			pthread_mutex_unlock(&thread_context->data_mutex);

			/* In case of shutdown a signal may be missing. */
			if (ret == ETIMEDOUT)
				continue;
		} else {
			/* Wait until next period */
			increment_period(&wakeup_time, cycle_time_ns);

			do {
				ret = clock_nanosleep(app_config.application_clock_id,
						      TIMER_ABSTIME, &wakeup_time, NULL);
			} while (ret == EINTR);

			if (ret) {
				log_message(LOG_LEVEL_ERROR,
					    "RtcTx: clock_nanosleep() failed: %s\n", strerror(ret));
				return NULL;
			}
		}

		/*
		 * Send RtcFrames, two possibilites:
		 *  a) Generate it, or
		 *  b) Use received ones if mirror enabled
		 */
		if (!mirror_enabled) {
			rtc_gen_and_send_xdp_frames(thread_context, xsk, sequence_counter,
						    &frame_number);
			sequence_counter += num_frames;
		} else {
			unsigned int received;
			uint64_t i;

			pthread_mutex_lock(&thread_context->xdp_data_mutex);

			received = thread_context->received_frames;

			sequence_counter = thread_context->rx_sequence_counter - received;

			/*
			 * The XDP receiver stored the frames within the umem area and populated the
			 * Tx ring. Now, the Tx ring can be committed to the kernel. Furthermore,
			 * already transmitted frames from last cycle can be recycled for Rx.
			 */

			xsk_ring_prod__submit(&xsk->tx, received);

			if (received > 0) {
				if (rtc_config->tx_hwtstamp_enabled) {
					/*
					 * Once-per-cycle: record TX SW timestamp for the first
					 * packet in this cycle and count all frames
					 */
					stat_frames_sent_batch(RTC_FRAME_TYPE, sequence_counter,
							       received);
				} else {
					for (i = sequence_counter; i < sequence_counter + received;
					     ++i)
						stat_frame_sent(RTC_FRAME_TYPE, i);
				}
			}

			xsk->outstanding_tx += received;
			thread_context->received_frames = 0;
			xdp_complete_tx(xsk);

#ifdef TX_TIMESTAMP
			if (received > 0 && rtc_config->tx_hwtstamp_enabled) {
				/*
				 * TX HW timestamp becomes available in the next cycle
				 * after the packet is transmitted.
				 * This is one cycle later than SW timestamp tracked
				 * using sequence_counter
				 */
				xsk->tx_hwts.seq_lagged = sequence_counter;
			}
#endif

			pthread_mutex_unlock(&thread_context->xdp_data_mutex);
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

static void *rtc_rx_thread_routine(void *data)
{
	struct thread_context *thread_context = data;
	const uint64_t cycle_time_ns = app_config.application_base_cycle_time_ns;
	struct timespec wakeup_time;
	int socket_fd, ret;

	socket_fd = thread_context->socket_fd;

	prepare_openssl(thread_context->rx_security_context);

	ret = get_thread_start_time(app_config.application_rx_base_offset_ns, &wakeup_time);
	if (ret) {
		log_message(LOG_LEVEL_ERROR, "RtcRx: Failed to calculate thread start time: %s!\n",
			    strerror(errno));
		return NULL;
	}

	while (!thread_context->stop) {
		struct packet_receive_request recv_req = {
			.traffic_class = thread_context->traffic_class,
			.socket_fd = socket_fd,
			.receive_function = receive_profinet_frame,
			.data = thread_context,
		};

		/* Wait until next period. */
		increment_period(&wakeup_time, cycle_time_ns);

		do {
			ret = clock_nanosleep(app_config.application_clock_id, TIMER_ABSTIME,
					      &wakeup_time, NULL);
		} while (ret == EINTR);

		if (ret) {
			log_message(LOG_LEVEL_ERROR, "RtcRx: clock_nanosleep() failed: %s\n",
				    strerror(ret));
			return NULL;
		}

		/* Receive Rtc frames. */
		packet_receive_messages(thread_context->packet_context, &recv_req);
	}

	return NULL;
}

static void *rtc_xdp_rx_thread_routine(void *data)
{
	struct thread_context *thread_context = data;
	const long long cycle_time_ns = app_config.application_base_cycle_time_ns;
	const struct traffic_class_config *rtc_config = thread_context->conf;
	const bool mirror_enabled = rtc_config->rx_mirror_enabled;
	const size_t frame_length = rtc_config->frame_length;
	struct xdp_socket *xsk = thread_context->xsk;
	struct timespec wakeup_time;
	int ret;

	prepare_openssl(thread_context->rx_security_context);

	ret = get_thread_start_time(app_config.application_rx_base_offset_ns, &wakeup_time);
	if (ret) {
		log_message(LOG_LEVEL_ERROR, "RtcRx: Failed to calculate thread start time: %s!\n",
			    strerror(errno));
		return NULL;
	}

	while (!thread_context->stop) {
		unsigned int received;

		/* Wait until next period */
		increment_period(&wakeup_time, cycle_time_ns);

		do {
			ret = clock_nanosleep(app_config.application_clock_id, TIMER_ABSTIME,
					      &wakeup_time, NULL);
		} while (ret == EINTR);

		if (ret) {
			log_message(LOG_LEVEL_ERROR, "RtcRx: clock_nanosleep() failed: %s\n",
				    strerror(ret));
			return NULL;
		}

		pthread_mutex_lock(&thread_context->xdp_data_mutex);
		received = xdp_receive_frames(xsk, frame_length, mirror_enabled,
					      receive_profinet_frame, thread_context, NULL);
		thread_context->received_frames = received;
		pthread_mutex_unlock(&thread_context->xdp_data_mutex);
	}

	return NULL;
}

int rtc_threads_create(struct thread_context *thread_context)
{
	struct traffic_class_config *rtc_config;
	int ret;

	if (!config_is_traffic_class_active("Rtc"))
		goto out;

	init_mutex(&thread_context->data_mutex);
	init_mutex(&thread_context->xdp_data_mutex);
	init_condition_variable(&thread_context->data_cond_var);

	thread_context->conf = rtc_config = &app_config.classes[RTC_FRAME_TYPE];
	thread_context->frame_type = RTC_FRAME_TYPE;
	thread_context->traffic_class = stat_frame_type_to_string(RTC_FRAME_TYPE);
	thread_context->frame_id =
		rtc_config->security_mode == SECURITY_MODE_NONE ? RTC_FRAMEID : RTC_SEC_FRAMEID;

	/* For XDP the frames are stored in a umem area. That memory is part of the socket. */
	if (!rtc_config->xdp_enabled) {
		thread_context->packet_context = packet_init(rtc_config->num_frames_per_cycle);
		if (!thread_context->packet_context) {
			fprintf(stderr, "Failed to allocate Rtc packet context!\n");
			ret = -ENOMEM;
			goto err_packet;
		}

		thread_context->tx_frame_data =
			calloc(rtc_config->num_frames_per_cycle, MAX_FRAME_SIZE);
		if (!thread_context->tx_frame_data) {
			fprintf(stderr, "Failed to allocate RtcTxFrameData!\n");
			ret = -ENOMEM;
			goto err_tx;
		}

		thread_context->rx_frame_data =
			calloc(rtc_config->num_frames_per_cycle, MAX_FRAME_SIZE);
		if (!thread_context->rx_frame_data) {
			fprintf(stderr, "Failed to allocate RtcRxFrameData!\n");
			ret = -ENOMEM;
			goto err_rx;
		}
	}

	/* Initialize data structures for AE */
	thread_context->frame_copy = calloc(1, MAX_FRAME_SIZE);
	if (!thread_context->frame_copy) {
		fprintf(stderr, "Failed to allocate RtcPayloadPattern for AE!\n");
		ret = -ENOMEM;
		goto err_payload;
	}

	thread_context->payload_pattern = thread_context->frame_copy +
					  sizeof(struct vlan_ethernet_header) +
					  sizeof(struct profinet_secure_header);
	thread_context->payload_pattern_length =
		rtc_config->frame_length - sizeof(struct vlan_ethernet_header) -
		sizeof(struct profinet_secure_header) - sizeof(struct security_checksum);

	/* For XDP a AF_XDP socket is allocated. Otherwise a Linux raw socket is used. */
	if (rtc_config->xdp_enabled) {
		thread_context->socket_fd = 0;
		thread_context->xsk = xdp_open_socket(
			rtc_config->interface, app_config.application_xdp_program,
			rtc_config->rx_queue, rtc_config->xdp_skb_mode, rtc_config->xdp_zc_mode,
			rtc_config->xdp_wakeup_mode, rtc_config->xdp_busy_poll_mode, false,
			rtc_config->tx_hwtstamp_enabled);
		if (!thread_context->xsk) {
			fprintf(stderr, "Failed to create Rtc Xdp socket!\n");
			ret = -ENOMEM;
			goto err_socket;
		}
	} else {
		thread_context->xsk = NULL;
		thread_context->socket_fd = create_rtc_socket();
		if (thread_context->socket_fd < 0) {
			fprintf(stderr, "Failed to create RtcSocket!\n");
			ret = -errno;
			goto err_socket;
		}
	}

	/* Same as above. For XDP the umem area is used. */
	if (rtc_config->rx_mirror_enabled && !rtc_config->xdp_enabled) {
		/* Per period the expectation is: RtcNumFramesPerCycle * MAX_FRAME */
		thread_context->mirror_buffer =
			ring_buffer_allocate(MAX_FRAME_SIZE * rtc_config->num_frames_per_cycle);
		if (!thread_context->mirror_buffer) {
			fprintf(stderr, "Failed to allocate Rtc Mirror RingBuffer!\n");
			ret = -ENOMEM;
			goto err_thread;
		}
	}

	if (rtc_config->security_mode != SECURITY_MODE_NONE) {
		thread_context->tx_security_context = security_init(
			rtc_config->security_algorithm, (unsigned char *)rtc_config->security_key);
		if (!thread_context->tx_security_context) {
			fprintf(stderr, "Failed to initialize Tx security context!\n");
			ret = -ENOMEM;
			goto err_tx_sec;
		}

		thread_context->rx_security_context = security_init(
			rtc_config->security_algorithm, (unsigned char *)rtc_config->security_key);
		if (!thread_context->rx_security_context) {
			fprintf(stderr, "Failed to initialize Rx security context!\n");
			ret = -ENOMEM;
			goto err_rx_sec;
		}
	} else {
		thread_context->tx_security_context = NULL;
		thread_context->rx_security_context = NULL;
	}

	ret = create_rt_thread(&thread_context->tx_task_id, "RtcTxThread",
			       rtc_config->tx_thread_priority, rtc_config->tx_thread_cpu,
			       rtc_config->xdp_enabled ? rtc_xdp_tx_thread_routine
						       : rtc_tx_thread_routine,
			       thread_context);
	if (ret) {
		fprintf(stderr, "Failed to create Rtc Tx thread!\n");
		goto err_thread_create1;
	}

	ret = create_rt_thread(&thread_context->rx_task_id, "RtcRxThread",
			       rtc_config->rx_thread_priority, rtc_config->rx_thread_cpu,
			       rtc_config->xdp_enabled ? rtc_xdp_rx_thread_routine
						       : rtc_rx_thread_routine,
			       thread_context);
	if (ret) {
		fprintf(stderr, "Failed to create Rtc Rx thread!\n");
		goto err_thread_create2;
	}

	thread_context->meta_data_offset =
		get_meta_data_offset(RTC_FRAME_TYPE, rtc_config->security_mode);

out:
	return 0;

err_thread_create2:
	thread_context->stop = 1;
	pthread_join(thread_context->tx_task_id, NULL);
err_thread_create1:
	security_exit(thread_context->rx_security_context);
err_rx_sec:
	security_exit(thread_context->tx_security_context);
err_tx_sec:
	ring_buffer_free(thread_context->mirror_buffer);
err_thread:
	if (thread_context->socket_fd)
		close(thread_context->socket_fd);
	if (thread_context->xsk)
		xdp_close_socket(thread_context->xsk, rtc_config->interface,
				 rtc_config->xdp_skb_mode);
err_socket:
	free(thread_context->frame_copy);
err_payload:
	free(thread_context->rx_frame_data);
err_rx:
	free(thread_context->tx_frame_data);
err_tx:
	packet_free(thread_context->packet_context);
err_packet:
	return ret;
}

void rtc_threads_free(struct thread_context *thread_context)
{
	struct traffic_class_config *rtc_config;

	if (!thread_context)
		return;

	rtc_config = thread_context->conf;

	free(thread_context->frame_copy);

	security_exit(thread_context->tx_security_context);
	security_exit(thread_context->rx_security_context);

	ring_buffer_free(thread_context->mirror_buffer);

	packet_free(thread_context->packet_context);
	free(thread_context->tx_frame_data);
	free(thread_context->rx_frame_data);

	if (thread_context->socket_fd > 0)
		close(thread_context->socket_fd);

	if (thread_context->xsk)
		xdp_close_socket(thread_context->xsk, rtc_config->interface,
				 rtc_config->xdp_skb_mode);
}

void rtc_threads_wait_for_finish(struct thread_context *thread_context)
{
	if (!thread_context)
		return;

	if (thread_context->rx_task_id)
		pthread_join(thread_context->rx_task_id, NULL);
	if (thread_context->tx_task_id)
		pthread_join(thread_context->tx_task_id, NULL);
}
