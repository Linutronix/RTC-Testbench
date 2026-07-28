// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2026 Linutronix GmbH
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
#include "security.h"
#include "stat.h"
#include "tc.h"
#include "thread.h"
#include "tx_time.h"
#include "utils.h"
#include "workload.h"
#include "xdp.h"

int tc_sleep_until(const struct thread_context *ctx, struct timespec *wakeup, uint64_t cycle_time)
{
	int ret;

	increment_period(wakeup, cycle_time);

	do {
		ret = clock_nanosleep(app_config.application_clock_id, TIMER_ABSTIME, wakeup, NULL);
	} while (ret == EINTR);

	if (ret)
		/* Called from RT context -> log_message(). */
		log_message(LOG_LEVEL_ERROR, "%s: clock_nanosleep() failed: %s\n",
			    ctx->traffic_class, strerror(ret));

	return ret;
}

int tc_wait_for_tx(struct thread_context *ctx)
{
	struct timespec timeout;
	int ret;

	clock_gettime(CLOCK_MONOTONIC, &timeout);
	timeout.tv_sec++;

	pthread_mutex_lock(&ctx->data_mutex);
	ret = pthread_cond_timedwait(&ctx->data_cond_var, &ctx->data_mutex, &timeout);
	pthread_mutex_unlock(&ctx->data_mutex);

	return ret;
}

int tc_wait_for_tx_burst(struct thread_context *ctx, size_t *num_frames)
{
	struct timespec timeout;
	int ret;

	clock_gettime(CLOCK_MONOTONIC, &timeout);
	timeout.tv_sec++;

	pthread_mutex_lock(&ctx->data_mutex);
	ret = pthread_cond_timedwait(&ctx->data_cond_var, &ctx->data_mutex, &timeout);
	*num_frames = ctx->num_frames_available;
	ctx->num_frames_available = 0;
	pthread_mutex_unlock(&ctx->data_mutex);

	return ret;
}

void tc_signal_next(struct thread_context *ctx)
{
	if (!ctx->next)
		return;

	pthread_mutex_lock(&ctx->next->data_mutex);
	pthread_cond_signal(&ctx->next->data_cond_var);
	pthread_mutex_unlock(&ctx->next->data_mutex);
}

static enum tc_tx_wait_result tc_wait_for_tx_cycle(struct thread_context *ctx,
						   struct timespec *wakeup_time, size_t *num_frames)
{
	const uint64_t cycle_time_ns = app_config.application_base_cycle_time_ns;
	const struct traffic_class_config *conf = ctx->conf;
	int ret;

	/*
	 * Burst traffic classes are triggered by the previous traffic class just like the
	 * cyclic ones. However, frames are only transmitted in cycles for which the Tx
	 * generation thread marked them as available.
	 */
	if (ctx->desc->tx_model == TC_TX_BURST) {
		ret = tc_wait_for_tx_burst(ctx, num_frames);
		return ret == ETIMEDOUT ? TC_TX_WAIT_STOP : TC_TX_WAIT_SEND;
	}

	*num_frames = conf->num_frames_per_cycle;

	if (!ctx->is_first) {
		/* In case of shutdown a signal may be missing. */
		ret = tc_wait_for_tx(ctx);
		return ret == ETIMEDOUT ? TC_TX_WAIT_STOP : TC_TX_WAIT_SEND;
	}

	ret = tc_sleep_until(ctx, wakeup_time, cycle_time_ns);

	return ret ? TC_TX_WAIT_ERROR : TC_TX_WAIT_SEND;
}

void *tc_tx_gen_thread(void *data)
{
	struct thread_context *ctx = data;
	const struct traffic_class_config *conf = ctx->conf;
	uint64_t num_frames = conf->num_frames_per_cycle;
	uint64_t cycle_time_ns = conf->burst_period_ns;
	pthread_mutex_t *mutex = &ctx->data_mutex;
	struct timespec wakeup_time;
	int ret;

	ret = get_thread_start_time(0, &wakeup_time);
	if (ret) {
		log_message(LOG_LEVEL_ERROR,
			    "%sTxGen: Failed to calculate thread start time: %s!\n",
			    ctx->traffic_class, strerror(errno));
		return NULL;
	}

	while (!ctx->stop) {
		/* Wait until next period */
		ret = tc_sleep_until(ctx, &wakeup_time, cycle_time_ns);
		if (ret)
			return NULL;

		/* Generate frames */
		pthread_mutex_lock(mutex);
		ctx->num_frames_available = num_frames;
		pthread_mutex_unlock(mutex);
	}

	return NULL;
}

static void tc_initialize_frames(struct thread_context *ctx, unsigned char *frame_data,
				 size_t num_frames, const unsigned char *source,
				 const unsigned char *destination)
{
	const struct traffic_class_desc *desc = ctx->desc;
	size_t i;

	for (i = 0; i < num_frames; i++) {
		unsigned char *frame = frame_idx(frame_data, i);
		size_t frame_length = MAX_FRAME_SIZE;

		/*
		 * In case both AF_XDP and Tx Launch Time or Tx HW Timestamp are enabled the payload
		 * starts at: frame_data + sizeof(struct xsk_tx_metadata)
		 */
#if defined(HAVE_XDP_TX_TIME) || defined(TX_TIMESTAMP)
		const struct traffic_class_config *conf = ctx->conf;

		if (conf->xdp_enabled && (conf->tx_time_enabled || conf->tx_hwtstamp_enabled)) {
			frame += sizeof(struct xsk_tx_metadata);
			frame_length -= sizeof(struct xsk_tx_metadata);
		}
#endif

		desc->ops.initialize_frame(ctx, frame, frame_length, source, destination);
	}
}

static int tc_send_messages(struct thread_context *ctx, int socket_fd,
			    struct sockaddr_ll *destination, unsigned char *frame_data,
			    size_t num_frames, uint64_t duration)
{
	const struct traffic_class_config *conf = ctx->conf;
	struct packet_send_request send_req = {
		.traffic_class = ctx->traffic_class,
		.socket_fd = socket_fd,
		.destination = destination,
		.frame_data = frame_data,
		.num_frames = num_frames,
		.frame_length = conf->frame_length,
		.duration = duration,
		.tx_time_offset = conf->tx_time_offset_ns,
		.meta_data_offset = ctx->meta_data_offset,
		.mirror_enabled = conf->rx_mirror_enabled,
		.tx_time_enabled = conf->tx_time_enabled,
	};

	return packet_send_messages(ctx->packet_context, &send_req);
}

static int tc_send_frames(struct thread_context *ctx, unsigned char *frame_data, size_t num_frames,
			  int socket_fd, struct sockaddr_ll *destination, uint64_t duration)
{
	const struct traffic_class_config *conf = ctx->conf;
	int len, i;

	/* Adjust meta data */
	set_mirror_tx_timestamp(conf, frame_data, conf->frame_length, num_frames,
				ctx->meta_data_offset);

	/* Send it */
	len = tc_send_messages(ctx, socket_fd, destination, frame_data, num_frames, duration);

	for (i = 0; i < len; i++) {
		uint64_t sequence_counter;

		sequence_counter =
			get_sequence_counter(frame_data + i * conf->frame_length,
					     ctx->meta_data_offset, conf->num_frames_per_cycle);

		stat_frame_sent(ctx->frame_type, sequence_counter);
	}

	return len;
}

static int tc_gen_and_send_frames(struct thread_context *ctx, int socket_fd,
				  struct sockaddr_ll *destination, uint64_t sequence_counter_begin,
				  uint64_t duration)
{
	const struct traffic_class_config *conf = ctx->conf;
	struct timespec tx_time = {};
	int len, i;

	app_clock_get(&tx_time);

	for (i = 0; i < conf->num_frames_per_cycle; i++) {
		struct prepare_frame_config frame_config;
		int err;

		frame_config.mode = conf->security_mode;
		frame_config.security_context = ctx->tx_security_context;
		frame_config.iv_prefix = (const unsigned char *)conf->security_iv_prefix;
		frame_config.payload_pattern = ctx->payload_pattern;
		frame_config.payload_pattern_length = ctx->payload_pattern_length;
		frame_config.frame_data = frame_idx(ctx->tx_frame_data, i);
		frame_config.frame_length = conf->frame_length;
		frame_config.num_frames_per_cycle = conf->num_frames_per_cycle;
		frame_config.sequence_counter = sequence_counter_begin + i;
		frame_config.tx_timestamp = ts_to_ns(&tx_time);
		frame_config.meta_data_offset = ctx->meta_data_offset;
		frame_config.frame_type = ctx->frame_type;
		frame_config.protocol_type = GENERICL2_PROTOCOL_TYPE;

		err = prepare_frame_for_tx(&frame_config);
		if (err)
			log_message(LOG_LEVEL_ERROR, "%sTx: Failed to prepare frame for Tx!\n",
				    ctx->traffic_class);
	}

	/* Send it */
	len = tc_send_messages(ctx, socket_fd, destination, ctx->tx_frame_data,
			       conf->num_frames_per_cycle, duration);

	if (len > 0)
		stat_frames_sent_batch(ctx->frame_type, sequence_counter_begin, len);

	return len;
}

static void tc_gen_and_send_xdp_frames(struct thread_context *ctx, struct xdp_socket *xsk,
				       uint64_t sequence_counter, uint64_t duration,
				       uint32_t *frame_number)
{
	const struct traffic_class_config *conf = ctx->conf;
	struct xdp_tx_time tx_time = {
		.traffic_class = ctx->traffic_class,
		.tx_time_offset = conf->tx_time_offset_ns,
		.num_frames_per_cycle = conf->num_frames_per_cycle,
		.sequence_counter_begin = sequence_counter,
		.duration = duration,
	};
	struct xdp_gen_config xdp = {
		.mode = conf->security_mode,
		.security_context = ctx->tx_security_context,
		.iv_prefix = (const unsigned char *)conf->security_iv_prefix,
		.payload_pattern = ctx->payload_pattern,
		.payload_pattern_length = ctx->payload_pattern_length,
		.frame_length = conf->frame_length,
		.num_frames_per_cycle = conf->num_frames_per_cycle,
		.frame_number = frame_number,
		.sequence_counter_begin = sequence_counter,
		.meta_data_offset = ctx->meta_data_offset,
		.frame_type = ctx->frame_type,
		.tx_time = conf->tx_time_enabled ? &tx_time : NULL,
		.protocol_type = GENERICL2_PROTOCOL_TYPE,
	};

	xdp_gen_and_send_frames(xsk, &xdp);
}

void *tc_tx_thread(void *data)
{
	struct thread_context *ctx = data;
	const struct traffic_class_config *conf = ctx->conf;
	size_t received_frames_length = MAX_FRAME_SIZE * conf->num_frames_per_cycle;
	struct security_context *security_context = ctx->tx_security_context;
	unsigned char *received_frames = ctx->rx_frame_data;
	const bool mirror_enabled = conf->rx_mirror_enabled;
	struct sockaddr_ll destination;
	uint64_t sequence_counter = 0;
	struct timespec wakeup_time;
	unsigned int if_index;
	uint32_t link_speed;
	int ret, socket_fd;
	uint64_t duration;

	socket_fd = ctx->socket_fd;

	ret = get_interface_link_speed(conf->interface, &link_speed);
	if (ret) {
		log_message(LOG_LEVEL_ERROR, "%sTx: Failed to get link speed!\n",
			    ctx->traffic_class);
		return NULL;
	}

	if_index = if_nametoindex(conf->interface);
	if (!if_index) {
		log_message(LOG_LEVEL_ERROR, "%sTx: if_nametoindex() failed!\n",
			    ctx->traffic_class);
		return NULL;
	}

	memset(&destination, '\0', sizeof(destination));
	destination.sll_family = PF_PACKET;
	destination.sll_ifindex = if_index;
	destination.sll_halen = ETH_ALEN;
	memcpy(destination.sll_addr, conf->l2_destination, ETH_ALEN);

	duration = tx_time_get_frame_duration(link_speed, conf->frame_length);

	tc_initialize_frames(ctx, ctx->tx_frame_data, conf->num_frames_per_cycle, ctx->source,
			     conf->l2_destination);

	prepare_openssl(security_context);
	tc_initialize_frames(ctx, ctx->frame_copy, 1, ctx->source, conf->l2_destination);

	ret = get_thread_start_time(app_config.application_tx_base_offset_ns, &wakeup_time);
	if (ret) {
		log_message(LOG_LEVEL_ERROR, "%sTx: Failed to calculate thread start time: %s!\n",
			    ctx->traffic_class, strerror(errno));
		return NULL;
	}

	while (!ctx->stop) {
		enum tc_tx_wait_result wait;
		size_t num_frames;

		wait = tc_wait_for_tx_cycle(ctx, &wakeup_time, &num_frames);
		if (wait == TC_TX_WAIT_STOP)
			continue;
		if (wait == TC_TX_WAIT_ERROR)
			return NULL;

		workload_check_finished(ctx);

		/*
		 * Send TC frames, two possibilites:
		 *  a) Generate it, or
		 *  b) Use received ones if mirror enabled
		 */
		if (!mirror_enabled) {
			if (num_frames) {
				tc_gen_and_send_frames(ctx, socket_fd, &destination,
						       sequence_counter, duration);

				sequence_counter += conf->num_frames_per_cycle;
			}
		} else {
			size_t len;

			ring_buffer_fetch(ctx->mirror_buffer, received_frames,
					  received_frames_length, &len);

			/* Len should be a multiple of frame size */
			num_frames = len / conf->frame_length;
			tc_send_frames(ctx, received_frames, num_frames, socket_fd, &destination,
				       duration);
		}

		tc_signal_next(ctx);

		if (ctx->is_last)
			stat_update();
	}

	return NULL;
}

void *tc_xdp_tx_thread(void *data)
{
	struct thread_context *ctx = data;
	const struct traffic_class_config *conf = ctx->conf;
	struct security_context *security_context = ctx->tx_security_context;
	uint32_t frame_number = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	const bool mirror_enabled = conf->rx_mirror_enabled;
	uint64_t sequence_counter = 0;
	struct timespec wakeup_time;
	unsigned char *frame_data;
	struct xdp_socket *xsk;
	uint32_t link_speed;
	uint64_t duration;
	int ret;

	xsk = ctx->xsk;
	xsk->tx_hwts.rtt = &round_trip_contexts[ctx->frame_type];
	xsk->tx_hwts.frames_per_cycle = conf->num_frames_per_cycle;
	xsk->tx_hwts.meta_data_offset = ctx->meta_data_offset;

	ret = get_interface_link_speed(conf->interface, &link_speed);
	if (ret) {
		log_message(LOG_LEVEL_ERROR, "%sTx: Failed to get link speed!\n",
			    ctx->traffic_class);
		return NULL;
	}

	duration = tx_time_get_frame_duration(link_speed, conf->frame_length);

	/* First half of umem area is for Rx, the second half is for Tx. */
	frame_data = xsk_umem__get_data(xsk->umem.buffer,
					XDP_FRAME_SIZE * XSK_RING_PROD__DEFAULT_NUM_DESCS);

	/* Initialize all Tx frames */
	tc_initialize_frames(ctx, frame_data, XSK_RING_CONS__DEFAULT_NUM_DESCS, ctx->source,
			     conf->l2_destination);

	prepare_openssl(security_context);
	tc_initialize_frames(ctx, ctx->frame_copy, 1, ctx->source, conf->l2_destination);

	ret = get_thread_start_time(app_config.application_tx_base_offset_ns, &wakeup_time);
	if (ret) {
		log_message(LOG_LEVEL_ERROR, "%sTx: Failed to calculate thread start time: %s!\n",
			    ctx->traffic_class, strerror(errno));
		return NULL;
	}

	while (!ctx->stop) {
		enum tc_tx_wait_result wait;
		size_t num_frames;

		wait = tc_wait_for_tx_cycle(ctx, &wakeup_time, &num_frames);
		if (wait == TC_TX_WAIT_STOP)
			continue;
		if (wait == TC_TX_WAIT_ERROR)
			return NULL;

		workload_check_finished(ctx);

		/*
		 * Send TC frames, two possibilites:
		 *  a) Generate it, or
		 *  b) Use received ones if mirror enabled
		 */
		if (!mirror_enabled) {
			if (num_frames) {
				tc_gen_and_send_xdp_frames(ctx, xsk, sequence_counter, duration,
							   &frame_number);
				sequence_counter += num_frames;
			}
		} else {
			unsigned int received;

			pthread_mutex_lock(&ctx->xdp_data_mutex);

			received = ctx->received_frames;

			sequence_counter = ctx->rx_sequence_counter - received;

			/*
			 * The XDP receiver stored the frames within the umem area and populated the
			 * Tx ring. Now, the Tx ring can be committed to the kernel. Furthermore,
			 * already transmitted frames from last cycle can be recycled for Rx.
			 */

			xsk_ring_prod__submit(&xsk->tx, received);

			if (received > 0)
				stat_frames_sent_batch(ctx->frame_type, sequence_counter, received);

			xsk->outstanding_tx += received;
			ctx->received_frames = 0;
			xdp_complete_tx(xsk);

			pthread_mutex_unlock(&ctx->xdp_data_mutex);
		}

		tc_signal_next(ctx);

		if (ctx->is_last)
			stat_update();
	}

	return NULL;
}

void *tc_rx_thread(void *data)
{
	struct thread_context *ctx = data;
	const uint64_t cycle_time_ns = app_config.application_base_cycle_time_ns;
	int socket_fd, ret, received;
	struct timespec wakeup_time;

	socket_fd = ctx->socket_fd;

	prepare_openssl(ctx->rx_security_context);

	ret = get_thread_start_time(app_config.application_rx_base_offset_ns, &wakeup_time);
	if (ret) {
		log_message(LOG_LEVEL_ERROR, "%sRx: Failed to calculate thread start time: %s!\n",
			    ctx->traffic_class, strerror(errno));
		return NULL;
	}

	while (!ctx->stop) {
		struct packet_receive_request recv_req = {
			.traffic_class = ctx->traffic_class,
			.socket_fd = socket_fd,
			.receive_function = ctx->desc->ops.receive_frame,
			.data = ctx,
		};

		/* Wait until next period. */
		ret = tc_sleep_until(ctx, &wakeup_time, cycle_time_ns);
		if (ret)
			return NULL;

		/* Receive TC frames. */
		received = packet_receive_messages(ctx->packet_context, &recv_req);

		workload_signal(ctx, received);
	}

	return NULL;
}

void *tc_xdp_rx_thread(void *data)
{
	struct thread_context *ctx = data;
	const uint64_t cycle_time_ns = app_config.application_base_cycle_time_ns;
	const struct traffic_class_config *conf = ctx->conf;
	const bool mirror_enabled = conf->rx_mirror_enabled;
	const size_t frame_length = conf->frame_length;
	struct xdp_socket *xsk = ctx->xsk;
	struct timespec wakeup_time;
	uint32_t link_speed;
	uint64_t duration;
	int ret;

	prepare_openssl(ctx->rx_security_context);

	ret = get_thread_start_time(app_config.application_rx_base_offset_ns, &wakeup_time);
	if (ret) {
		log_message(LOG_LEVEL_ERROR, "%sRx: Failed to calculate thread start time: %s!\n",
			    ctx->traffic_class, strerror(errno));
		return NULL;
	}

	ret = get_interface_link_speed(conf->interface, &link_speed);
	if (ret) {
		log_message(LOG_LEVEL_ERROR, "%sRx: Failed to get link speed!\n",
			    ctx->traffic_class);
		return NULL;
	}

	duration = tx_time_get_frame_duration(link_speed, conf->frame_length);

	while (!ctx->stop) {
		struct xdp_tx_time tx_time = {
			.tx_time_offset = conf->tx_time_offset_ns,
			.duration = duration,
			.num_frames_per_cycle = conf->num_frames_per_cycle,
			.sequence_counter_begin = 0,
			.traffic_class = ctx->traffic_class,
		};
		unsigned int received;

		/* Wait until next period */
		ret = tc_sleep_until(ctx, &wakeup_time, cycle_time_ns);
		if (ret)
			return NULL;

		pthread_mutex_lock(&ctx->xdp_data_mutex);
		received = xdp_receive_frames(xsk, frame_length, mirror_enabled,
					      ctx->desc->ops.receive_frame, ctx, &tx_time);
		ctx->received_frames = received;
		pthread_mutex_unlock(&ctx->xdp_data_mutex);

		workload_signal(ctx, received);
	}

	return NULL;
}

int tc_threads_create(struct thread_context *ctx)
{
	struct traffic_class_config *conf = ctx->conf;
	int ret;

	init_mutex(&ctx->data_mutex);
	init_mutex(&ctx->xdp_data_mutex);
	init_condition_variable(&ctx->data_cond_var);

	/* For XDP the frames are stored in a umem area. That memory is part of the socket. */
	if (!conf->xdp_enabled) {
		ctx->packet_context = packet_init(conf->num_frames_per_cycle);
		if (!ctx->packet_context) {
			fprintf(stderr, "Failed to allocate %s packet context!\n",
				ctx->traffic_class);
			ret = -ENOMEM;
			goto err_packet;
		}

		ctx->tx_frame_data = calloc(conf->num_frames_per_cycle, MAX_FRAME_SIZE);
		if (!ctx->tx_frame_data) {
			fprintf(stderr, "Failed to allocate %sTxFrameData!\n", ctx->traffic_class);
			ret = -ENOMEM;
			goto err_tx;
		}

		ctx->rx_frame_data = calloc(conf->num_frames_per_cycle, MAX_FRAME_SIZE);
		if (!ctx->rx_frame_data) {
			fprintf(stderr, "Failed to allocate %sRxFrameData!\n", ctx->traffic_class);
			ret = -ENOMEM;
			goto err_rx;
		}
	}

	ret = get_interface_mac_address(conf->interface, ctx->source, sizeof(ctx->source));
	if (ret) {
		fprintf(stderr, "Failed to get %s Source MAC address!\n", ctx->traffic_class);
		goto err_mac;
	}

	/* Initialize data structures for AE */
	ctx->frame_copy = calloc(1, MAX_FRAME_SIZE);
	if (!ctx->frame_copy) {
		fprintf(stderr, "Failed to allocate %sPayloadPattern for AE!\n",
			ctx->traffic_class);
		ret = -ENOMEM;
		goto err_payload;
	}

	ctx->payload_pattern = ctx->frame_copy + sizeof(struct vlan_ethernet_header) +
			       sizeof(struct profinet_secure_header);
	ctx->payload_pattern_length = conf->frame_length - sizeof(struct vlan_ethernet_header) -
				      sizeof(struct profinet_secure_header) -
				      sizeof(struct security_checksum);

	/* For XDP a AF_XDP socket is allocated. Otherwise a Linux raw socket is used. */
	if (conf->xdp_enabled) {
		ctx->socket_fd = 0;
		ctx->xsk = xdp_open_socket(conf->interface, app_config.application_xdp_program,
					   conf->rx_queue, conf->xdp_skb_mode, conf->xdp_zc_mode,
					   conf->xdp_wakeup_mode, conf->xdp_busy_poll_mode,
					   conf->tx_time_enabled, conf->tx_hwtstamp_enabled);
		if (!ctx->xsk) {
			fprintf(stderr, "Failed to create %s Xdp socket!\n", ctx->traffic_class);
			ret = -ENOMEM;
			goto err_socket;
		}
	} else {
		ctx->xsk = NULL;
		ctx->socket_fd = ctx->desc->ops.create_socket();
		if (ctx->socket_fd < 0) {
			fprintf(stderr, "Failed to create %sSocket!\n", ctx->traffic_class);
			ret = -errno;
			goto err_socket;
		}
	}

	/* Same as above. For XDP the umem area is used. */
	if (conf->rx_mirror_enabled && !conf->xdp_enabled) {
		/* Per period the expectation is: NumFramesPerCycle * MAX_FRAME */
		ctx->mirror_buffer =
			ring_buffer_allocate(MAX_FRAME_SIZE * conf->num_frames_per_cycle);
		if (!ctx->mirror_buffer) {
			fprintf(stderr, "Failed to allocate %s Mirror RingBuffer!\n",
				ctx->traffic_class);
			ret = -ENOMEM;
			goto err_thread;
		}
	}

	if (conf->security_mode != SECURITY_MODE_NONE) {
		ctx->tx_security_context = security_init(conf->security_algorithm,
							 (unsigned char *)conf->security_key);
		if (!ctx->tx_security_context) {
			fprintf(stderr, "Failed to initialize Tx security context!\n");
			ret = -ENOMEM;
			goto err_tx_sec;
		}

		ctx->rx_security_context = security_init(conf->security_algorithm,
							 (unsigned char *)conf->security_key);
		if (!ctx->rx_security_context) {
			fprintf(stderr, "Failed to initialize Rx security context!\n");
			ret = -ENOMEM;
			goto err_rx_sec;
		}
	} else {
		ctx->tx_security_context = NULL;
		ctx->rx_security_context = NULL;
	}

	ctx->meta_data_offset = get_meta_data_offset(ctx->frame_type, conf->security_mode);

	ret = create_rt_thread(&ctx->tx_task_id, conf->tx_thread_priority, conf->tx_thread_cpu,
			       ctx->desc->ops.tx_thread, ctx, "%sTxThread", ctx->traffic_class);
	if (ret) {
		fprintf(stderr, "Failed to create %s Tx thread!\n", ctx->traffic_class);
		goto err_thread_tx;
	}

	if (ctx->desc->tx_model == TC_TX_BURST && !conf->rx_mirror_enabled) {
		ret = create_rt_thread(&ctx->tx_gen_task_id, conf->tx_thread_priority,
				       conf->tx_thread_cpu, tc_tx_gen_thread, ctx, "%sTxGenThread",
				       ctx->traffic_class);
		if (ret) {
			fprintf(stderr, "Failed to create %s TxGen Thread!\n", ctx->traffic_class);
			goto err_thread_txgen;
		}
	}

	ret = create_rt_thread(&ctx->rx_task_id, conf->rx_thread_priority, conf->rx_thread_cpu,
			       ctx->desc->ops.rx_thread, ctx, "%sRxThread", ctx->traffic_class);
	if (ret) {
		fprintf(stderr, "Failed to create %s Rx thread!\n", ctx->traffic_class);
		goto err_thread_rx;
	}

	/* Create workload thread for execution after network RX */
	ret = workload_context_init(ctx);
	if (ret) {
		fprintf(stderr, "Failed to create %s Workload context!\n", ctx->traffic_class);
		goto err_thread_wl;
	}

	return 0;

err_thread_wl:
	ctx->stop = 1;
	pthread_join(ctx->rx_task_id, NULL);
err_thread_rx:
	ctx->stop = 1;
	if (ctx->tx_gen_task_id)
		pthread_join(ctx->tx_gen_task_id, NULL);
err_thread_txgen:
	ctx->stop = 1;
	pthread_join(ctx->tx_task_id, NULL);
err_thread_tx:
	security_exit(ctx->rx_security_context);
err_rx_sec:
	security_exit(ctx->tx_security_context);
err_tx_sec:
	ring_buffer_free(ctx->mirror_buffer);
err_thread:
	if (ctx->socket_fd)
		close(ctx->socket_fd);
	if (ctx->xsk)
		xdp_close_socket(ctx->xsk, conf->interface, conf->xdp_skb_mode);
err_socket:
	free(ctx->frame_copy);
err_payload:
err_mac:
	free(ctx->rx_frame_data);
err_rx:
	free(ctx->tx_frame_data);
err_tx:
	packet_free(ctx->packet_context);
err_packet:
	return ret;
}

void tc_threads_wait_for_finish(struct thread_context *ctx)
{
	if (!ctx)
		return;

	workload_thread_wait_for_finish(ctx);

	if (ctx->rx_task_id)
		pthread_join(ctx->rx_task_id, NULL);
	if (ctx->tx_task_id)
		pthread_join(ctx->tx_task_id, NULL);
	if (ctx->tx_gen_task_id)
		pthread_join(ctx->tx_gen_task_id, NULL);
}

void tc_threads_free(struct thread_context *ctx)
{
	struct traffic_class_config *conf;

	if (!ctx)
		return;

	conf = ctx->conf;

	free(ctx->frame_copy);

	security_exit(ctx->tx_security_context);
	security_exit(ctx->rx_security_context);

	ring_buffer_free(ctx->mirror_buffer);

	packet_free(ctx->packet_context);
	free(ctx->tx_frame_data);
	free(ctx->rx_frame_data);

	if (ctx->socket_fd > 0)
		close(ctx->socket_fd);

	if (ctx->xsk)
		xdp_close_socket(ctx->xsk, conf->interface, conf->xdp_skb_mode);

	workload_thread_free(ctx);

	free(ctx->desc);

	/*
	 * FIXME: For some reason, l2 has a different allocation scheme than all other traffic
	 * traffic classes. Kein Kommentar.
	 */
	if (ctx->frame_type == GENERICL2_FRAME_TYPE)
		free(ctx);
}
