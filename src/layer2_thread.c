// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2022-2026 Linutronix GmbH
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

#include <sys/socket.h>

#include "app_config.h"

#include "config.h"
#include "layer2_thread.h"
#include "log.h"
#include "net.h"
#include "packet.h"
#include "security.h"
#include "stat.h"
#include "thread.h"
#include "tx_time.h"
#include "utils.h"
#include "workload.h"
#include "xdp.h"

static void generic_l2_initialize_frame(struct thread_context *thread_context,
					unsigned char *frame_data, const unsigned char *source,
					const unsigned char *destination)
{
	const struct traffic_class_config *l2_config = thread_context->conf;
	struct vlan_ethernet_header *eth;
	struct generic_l2_header *l2;
	size_t payload_offset;

	/*
	 * GenericL2Frame:
	 *   Destination
	 *   Source
	 *   VLAN tag
	 *   Ether type
	 *   Cycle counter
	 *   Payload
	 *   Padding to maxFrame
	 *
	 * In case both AF_XDP and Tx Launch Time or Tx HW Timestamp are enabled the payload starts
	 * at: frame_data + sizeof(struct xsk_tx_metadata)
	 */

#if defined(HAVE_XDP_TX_TIME) || defined(TX_TIMESTAMP)
	if (l2_config->xdp_enabled &&
	    (l2_config->tx_time_enabled || l2_config->tx_hwtstamp_enabled))
		frame_data += sizeof(struct xsk_tx_metadata);
#endif

	eth = (struct vlan_ethernet_header *)frame_data;
	l2 = (struct generic_l2_header *)(frame_data + sizeof(*eth));

	/* Ethernet header */
	memcpy(eth->destination, destination, ETH_ALEN);
	memcpy(eth->source, source, ETH_ALEN);

	/* VLAN Header */
	eth->vlan_proto = htons(ETH_P_8021Q);
	eth->vlantci = htons(l2_config->vid | l2_config->pcp << VLAN_PCP_SHIFT);
	eth->vlan_encapsulated_proto = htons(l2_config->ether_type);

	/* Generic L2 header */
	l2->meta_data.frame_counter = 0;
	l2->meta_data.cycle_counter = 0;

	/* Payload */
	payload_offset = sizeof(*eth) + sizeof(*l2);
	memcpy(frame_data + payload_offset, l2_config->payload_pattern,
	       l2_config->payload_pattern_length);

	/* Padding: '\0' */
}

static void generic_l2_initialize_frames(struct thread_context *thread_context,
					 unsigned char *frame_data, size_t num_frames,
					 const unsigned char *source,
					 const unsigned char *destination)
{
	size_t i;

	for (i = 0; i < num_frames; ++i)
		generic_l2_initialize_frame(thread_context, frame_idx(frame_data, i), source,
					    destination);
}

static int generic_l2_send_messages(struct thread_context *thread_context, int socket_fd,
				    struct sockaddr_ll *destination, unsigned char *frame_data,
				    size_t num_frames, uint64_t duration)
{
	const struct traffic_class_config *l2_config = thread_context->conf;
	struct packet_send_request send_req = {
		.traffic_class = thread_context->traffic_class,
		.socket_fd = socket_fd,
		.destination = destination,
		.frame_data = frame_data,
		.num_frames = num_frames,
		.frame_length = l2_config->frame_length,
		.duration = duration,
		.tx_time_offset = l2_config->tx_time_offset_ns,
		.meta_data_offset = thread_context->meta_data_offset,
		.mirror_enabled = l2_config->rx_mirror_enabled,
		.tx_time_enabled = l2_config->tx_time_enabled,
	};

	return packet_send_messages(thread_context->packet_context, &send_req);
}

static int generic_l2_send_frames(struct thread_context *thread_context, unsigned char *frame_data,
				  size_t num_frames, int socket_fd, struct sockaddr_ll *destination,
				  uint64_t duration)
{
	const struct traffic_class_config *l2_config = thread_context->conf;
	size_t frame_length;
	int len, i;

	/* Send it */
	frame_length = l2_config->frame_length;
	len = generic_l2_send_messages(thread_context, socket_fd, destination, frame_data,
				       num_frames, duration);

	for (i = 0; i < len; i++) {
		uint64_t sequence_counter;

		sequence_counter = get_sequence_counter(frame_data + i * frame_length,
							thread_context->meta_data_offset,
							l2_config->num_frames_per_cycle);
		stat_frame_sent(GENERICL2_FRAME_TYPE, sequence_counter);
	}

	return len;
}

static int generic_l2_gen_and_send_frames(struct thread_context *thread_context,
					  size_t num_frames_per_cycle, int socket_fd,
					  struct sockaddr_ll *destination,
					  uint64_t sequence_counter_begin, uint64_t duration)
{
	struct vlan_ethernet_header *eth;
	struct generic_l2_header *l2;
	struct timespec tx_time = {};
	int len, i;

	clock_gettime(app_config.application_clock_id, &tx_time);

	/* Adjust meta data */
	for (i = 0; i < num_frames_per_cycle; i++) {
		l2 = (struct generic_l2_header *)(frame_idx(thread_context->tx_frame_data, i) +
						  sizeof(*eth));
		sequence_counter_to_meta_data(&l2->meta_data, sequence_counter_begin + i,
					      num_frames_per_cycle);

		tx_timestamp_to_meta_data(&l2->meta_data, ts_to_ns(&tx_time));
	}

	/* Send them */
	len = generic_l2_send_messages(thread_context, socket_fd, destination,
				       thread_context->tx_frame_data, num_frames_per_cycle,
				       duration);

	for (i = 0; i < len; i++)
		stat_frame_sent(GENERICL2_FRAME_TYPE, sequence_counter_begin + i);

	return len;
}

static void generic_l2_gen_and_send_xdp_frames(struct thread_context *thread_context,
					       size_t num_frames_per_cycle,
					       uint64_t sequence_counter, uint64_t wakeup_time,
					       uint64_t duration, uint32_t *frame_number)
{
	const struct traffic_class_config *l2_config = thread_context->conf;
	struct xdp_tx_time tx_time = {
		.traffic_class = thread_context->traffic_class,
		.tx_time_offset = l2_config->tx_time_offset_ns,
		.num_frames_per_cycle = num_frames_per_cycle,
		.sequence_counter_begin = sequence_counter,
		.duration = duration,
	};
	struct xdp_gen_config xdp = {
		.mode = SECURITY_MODE_NONE,
		.security_context = NULL,
		.iv_prefix = NULL,
		.payload_pattern = NULL,
		.payload_pattern_length = 0,
		.frame_length = l2_config->frame_length,
		.num_frames_per_cycle = num_frames_per_cycle,
		.frame_number = frame_number,
		.sequence_counter_begin = sequence_counter,
		.meta_data_offset = thread_context->meta_data_offset,
		.frame_type = GENERICL2_FRAME_TYPE,
		.tx_time = l2_config->tx_time_enabled ? &tx_time : NULL,
	};

	xdp_gen_and_send_frames(thread_context->xsk, &xdp);
}

static void *generic_l2_tx_thread_routine(void *data)
{
	struct thread_context *thread_context = data;
	const struct traffic_class_config *l2_config = thread_context->conf;
	size_t received_frames_length = MAX_FRAME_SIZE * l2_config->num_frames_per_cycle;
	const long long cycle_time_ns = app_config.application_base_cycle_time_ns;
	const bool mirror_enabled = l2_config->rx_mirror_enabled;
	unsigned char *received_frames = thread_context->rx_frame_data;
	struct sockaddr_ll destination;
	unsigned char source[ETH_ALEN];
	uint64_t sequence_counter = 0;
	struct timespec wakeup_time;
	unsigned int if_index;
	uint32_t link_speed;
	uint64_t duration;
	int ret, socket_fd;

	socket_fd = thread_context->socket_fd;

	ret = get_interface_mac_address(l2_config->interface, source, ETH_ALEN);
	if (ret < 0) {
		log_message(LOG_LEVEL_ERROR, "GenericL2Tx: Failed to get Source MAC address!\n");
		return NULL;
	}

	ret = get_interface_link_speed(l2_config->interface, &link_speed);
	if (ret) {
		log_message(LOG_LEVEL_ERROR, "GenericL2Tx: Failed to get link speed!\n");
		return NULL;
	}

	if_index = if_nametoindex(l2_config->interface);
	if (!if_index) {
		log_message(LOG_LEVEL_ERROR, "GenericL2Tx: if_nametoindex() failed!\n");
		return NULL;
	}

	memset(&destination, '\0', sizeof(destination));
	destination.sll_family = PF_PACKET;
	destination.sll_ifindex = if_index;
	destination.sll_halen = ETH_ALEN;
	memcpy(destination.sll_addr, l2_config->l2_destination, ETH_ALEN);

	duration = tx_time_get_frame_duration(link_speed, l2_config->frame_length);

	generic_l2_initialize_frames(thread_context, thread_context->tx_frame_data,
				     l2_config->num_frames_per_cycle, source,
				     l2_config->l2_destination);

	ret = get_thread_start_time(app_config.application_tx_base_offset_ns, &wakeup_time);
	if (ret) {
		log_message(LOG_LEVEL_ERROR,
			    "GenericL2Tx: Failed to calculate thread start time: %s!\n",
			    strerror(errno));
		return NULL;
	}

	while (!thread_context->stop) {
		increment_period(&wakeup_time, cycle_time_ns);

		do {
			ret = clock_nanosleep(app_config.application_clock_id, TIMER_ABSTIME,
					      &wakeup_time, NULL);
		} while (ret == EINTR);

		if (ret) {
			log_message(LOG_LEVEL_ERROR, "GenericL2Tx: clock_nanosleep() failed: %s\n",
				    strerror(ret));
			return NULL;
		}

		workload_check_finished(thread_context);

		if (!mirror_enabled) {
			generic_l2_gen_and_send_frames(thread_context,
						       l2_config->num_frames_per_cycle, socket_fd,
						       &destination, sequence_counter, duration);

			sequence_counter += l2_config->num_frames_per_cycle;
		} else {
			size_t len, num_frames;

			ring_buffer_fetch(thread_context->mirror_buffer, received_frames,
					  received_frames_length, &len);

			/* Len should be a multiple of frame size */
			num_frames = len / l2_config->frame_length;
			generic_l2_send_frames(thread_context, received_frames, num_frames,
					       socket_fd, &destination, duration);
		}

		stat_update();
	}

	return NULL;
}

static void *generic_l2_xdp_tx_thread_routine(void *data)
{
	struct thread_context *thread_context = data;
	const long long cycle_time_ns = app_config.application_base_cycle_time_ns;
	const struct traffic_class_config *l2_config = thread_context->conf;
	const bool mirror_enabled = l2_config->rx_mirror_enabled;
	uint32_t frame_number = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	size_t num_frames = l2_config->num_frames_per_cycle;
	unsigned char source[ETH_ALEN];
	uint64_t sequence_counter = 0;
	struct timespec wakeup_time;
	unsigned char *frame_data;
	struct xdp_socket *xsk;
	uint32_t link_speed;
	uint64_t duration;
	int ret;

	xsk = thread_context->xsk;
	xsk->tx_hwts.rtt = &round_trip_contexts[GENERICL2_FRAME_TYPE];
	xsk->tx_hwts.frames_per_cycle = l2_config->num_frames_per_cycle;

	ret = get_interface_mac_address(l2_config->interface, source, ETH_ALEN);
	if (ret < 0) {
		log_message(LOG_LEVEL_ERROR, "GenericL2Tx: Failed to get Source MAC address!\n");
		return NULL;
	}

	ret = get_interface_link_speed(l2_config->interface, &link_speed);
	if (ret) {
		log_message(LOG_LEVEL_ERROR, "GenericL2Tx: Failed to get link speed!\n");
		return NULL;
	}

	duration = tx_time_get_frame_duration(link_speed, l2_config->frame_length);

	/* First half of umem area is for Rx, the second half is for Tx. */
	frame_data = xsk_umem__get_data(xsk->umem.buffer,
					XDP_FRAME_SIZE * XSK_RING_PROD__DEFAULT_NUM_DESCS);

	/* Initialize all Tx frames */
	generic_l2_initialize_frames(thread_context, frame_data, XSK_RING_CONS__DEFAULT_NUM_DESCS,
				     source, l2_config->l2_destination);

	ret = get_thread_start_time(app_config.application_tx_base_offset_ns, &wakeup_time);
	if (ret) {
		log_message(LOG_LEVEL_ERROR,
			    "GenericL2Tx: Failed to calculate thread start time: %s!\n",
			    strerror(errno));
		return NULL;
	}

	while (!thread_context->stop) {
		increment_period(&wakeup_time, cycle_time_ns);

		do {
			ret = clock_nanosleep(app_config.application_clock_id, TIMER_ABSTIME,
					      &wakeup_time, NULL);
		} while (ret == EINTR);

		if (ret) {
			log_message(LOG_LEVEL_ERROR, "GenericL2Tx: clock_nanosleep() failed: %s\n",
				    strerror(ret));
			return NULL;
		}

		workload_check_finished(thread_context);

		if (!mirror_enabled) {
			generic_l2_gen_and_send_xdp_frames(thread_context, num_frames,
							   sequence_counter, ts_to_ns(&wakeup_time),
							   duration, &frame_number);
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
				if (l2_config->tx_hwtstamp_enabled) {
					/*
					 * Once-per-cycle: record TX SW timestamp for the first
					 * packet in this cycle and count all frames
					 */
					stat_frames_sent_batch(GENERICL2_FRAME_TYPE,
							       sequence_counter, received);
				} else {
					for (i = sequence_counter; i < sequence_counter + received;
					     ++i)
						stat_frame_sent(GENERICL2_FRAME_TYPE, i);
				}
			}

			xsk->outstanding_tx += received;
			thread_context->received_frames = 0;
			xdp_complete_tx(xsk);

#ifdef TX_TIMESTAMP
			if (received > 0 && l2_config->tx_hwtstamp_enabled) {
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

		stat_update();
	}

	return NULL;
}

static int generic_l2_rx_frame(void *data, unsigned char *frame_data, size_t len)
{
	struct thread_context *thread_context = data;
	const struct traffic_class_config *l2_config = thread_context->conf;
	const unsigned char *expected_pattern = (const unsigned char *)l2_config->payload_pattern;
	const size_t expected_pattern_length = l2_config->payload_pattern_length;
	const size_t num_frames_per_cycle = l2_config->num_frames_per_cycle;
	const bool mirror_enabled = l2_config->rx_mirror_enabled;
	const bool ignore_rx_errors = l2_config->ignore_rx_errors;
	uint64_t tx_timestamp, rx_hw_timestamp, rx_sw_timestamp;
	size_t expected_frame_length = l2_config->frame_length;
	bool out_of_order, payload_mismatch, frame_id_mismatch;
	unsigned char new_frame[MAX_FRAME_SIZE];
	struct generic_l2_header *l2;
	uint64_t sequence_counter;
	bool vlan_tag_missing;
	void *p = frame_data;
	struct ethhdr *eth;
	uint16_t proto;

	if (len < sizeof(struct vlan_ethernet_header)) {
		log_message(LOG_LEVEL_WARNING, "GenericL2Rx: Too small frame received!\n");
		return -EINVAL;
	}

	eth = p;
	if (eth->h_proto == htons(ETH_P_8021Q)) {
		struct vlan_ethernet_header *veth = p;

		proto = veth->vlan_encapsulated_proto;
		p += sizeof(*veth);
		vlan_tag_missing = false;
	} else {
		proto = eth->h_proto;
		p += sizeof(*eth);
		expected_frame_length -= sizeof(struct vlan_header);
		vlan_tag_missing = true;
	}

	if (proto != htons(l2_config->ether_type)) {
		log_message(LOG_LEVEL_WARNING,
			    "GenericL2Rx: Frame with wrong Ether Type received!\n");
		return -EINVAL;
	}

	/* Check frame length: VLAN tag might be stripped or not. Check it. */
	if (len != expected_frame_length) {
		log_message(LOG_LEVEL_WARNING, "GenericL2Rx: Frame with wrong length received!\n");
		return -EINVAL;
	}

	/* Check cycle counter and payload. */
	l2 = p;
	p += sizeof(*l2);

	sequence_counter = meta_data_to_sequence_counter(&l2->meta_data, num_frames_per_cycle);

	tx_timestamp = meta_data_to_tx_timestamp(&l2->meta_data);
	set_mirror_tx_timestamp(&l2->meta_data);

	xdp_get_timestamp_metadata(frame_data, &rx_hw_timestamp, &rx_sw_timestamp);
	out_of_order = sequence_counter != thread_context->rx_sequence_counter;
	payload_mismatch = memcmp(p, expected_pattern, expected_pattern_length);
	frame_id_mismatch = false;

	stat_frame_received(GENERICL2_FRAME_TYPE, sequence_counter, out_of_order, payload_mismatch,
			    frame_id_mismatch, tx_timestamp, rx_hw_timestamp, rx_sw_timestamp);

	if (out_of_order) {
		if (!ignore_rx_errors)
			log_message(LOG_LEVEL_WARNING,
				    "GenericL2Rx: frame[%" PRIu64
				    "] SequenceCounter mismatch: %" PRIu64 "!\n",
				    sequence_counter, thread_context->rx_sequence_counter);
		thread_context->rx_sequence_counter++;
	}

	if (payload_mismatch)
		log_message(LOG_LEVEL_WARNING,
			    "GenericL2Rx: frame[%" PRIu64 "] Payload Pattern mismatch!\n",
			    sequence_counter);

	thread_context->rx_sequence_counter++;

	/*
	 * If mirror enabled, assemble and store the frame for Tx later.
	 *
	 * In case of XDP the Rx umem area will be reused for Tx.
	 */
	if (!mirror_enabled)
		return 0;

	if (l2_config->xdp_enabled) {
		/* Re-add vlan tag */
		if (vlan_tag_missing)
			insert_vlan_tag(frame_data, len, l2_config->ether_type,
					l2_config->vid | l2_config->pcp << VLAN_PCP_SHIFT);

		/* Swap mac addresses inline */
		swap_mac_addresses(frame_data, len);
	} else {
		/* Build new frame for Tx with VLAN info. */
		build_vlan_frame_from_rx(frame_data, len, new_frame, sizeof(new_frame),
					 l2_config->ether_type,
					 l2_config->vid | l2_config->pcp << VLAN_PCP_SHIFT);

		/* Store the new frame. */
		ring_buffer_add(thread_context->mirror_buffer, new_frame, len + 4);
	}

	return 0;
}

static void *generic_l2_rx_thread_routine(void *data)
{
	struct thread_context *thread_context = data;
	const uint64_t cycle_time_ns = app_config.application_base_cycle_time_ns;
	int socket_fd, ret, received;
	struct timespec wakeup_time;

	socket_fd = thread_context->socket_fd;

	ret = get_thread_start_time(app_config.application_rx_base_offset_ns, &wakeup_time);
	if (ret) {
		log_message(LOG_LEVEL_ERROR,
			    "GenericL2Rx: Failed to calculate thread start time: %s!\n",
			    strerror(errno));
		return NULL;
	}

	while (!thread_context->stop) {
		struct packet_receive_request recv_req = {
			.traffic_class = thread_context->traffic_class,
			.socket_fd = socket_fd,
			.receive_function = generic_l2_rx_frame,
			.data = thread_context,
		};

		/* Wait until next period. */
		increment_period(&wakeup_time, cycle_time_ns);

		do {
			ret = clock_nanosleep(app_config.application_clock_id, TIMER_ABSTIME,
					      &wakeup_time, NULL);
		} while (ret == EINTR);

		if (ret) {
			log_message(LOG_LEVEL_ERROR, "GenericL2Rx: clock_nanosleep() failed: %s\n",
				    strerror(ret));
			return NULL;
		}

		/* Receive Layer 2 frames. */
		received = packet_receive_messages(thread_context->packet_context, &recv_req);

		workload_signal(thread_context, received);
	}

	return NULL;
}

static void *generic_l2_xdp_rx_thread_routine(void *data)
{
	struct thread_context *thread_context = data;
	const long long cycle_time_ns = app_config.application_base_cycle_time_ns;
	const struct traffic_class_config *l2_config = thread_context->conf;
	const bool mirror_enabled = l2_config->rx_mirror_enabled;
	const size_t frame_length = l2_config->frame_length;
	struct xdp_socket *xsk = thread_context->xsk;
	struct timespec wakeup_time;
	uint32_t link_speed;
	uint64_t duration;
	int ret;

	ret = get_thread_start_time(app_config.application_rx_base_offset_ns, &wakeup_time);
	if (ret) {
		log_message(LOG_LEVEL_ERROR,
			    "GenericL2Rx: Failed to calculate thread start time: %s!\n",
			    strerror(errno));
		return NULL;
	}

	ret = get_interface_link_speed(l2_config->interface, &link_speed);
	if (ret) {
		log_message(LOG_LEVEL_ERROR, "GenericL2Rx: Failed to get link speed!\n");
		return NULL;
	}

	duration = tx_time_get_frame_duration(link_speed, l2_config->frame_length);

	while (!thread_context->stop) {
		struct xdp_tx_time tx_time = {
			.tx_time_offset = l2_config->tx_time_offset_ns,
			.duration = duration,
			.num_frames_per_cycle = l2_config->num_frames_per_cycle,
			.sequence_counter_begin = 0,
			.traffic_class = thread_context->traffic_class,
		};
		unsigned int received;

		/* Wait until next period */
		increment_period(&wakeup_time, cycle_time_ns);

		do {
			ret = clock_nanosleep(app_config.application_clock_id, TIMER_ABSTIME,
					      &wakeup_time, NULL);
		} while (ret == EINTR);

		if (ret) {
			log_message(LOG_LEVEL_ERROR, "GenericL2Rx: clock_nanosleep() failed: %s\n",
				    strerror(ret));
			return NULL;
		}

		pthread_mutex_lock(&thread_context->xdp_data_mutex);
		received = xdp_receive_frames(xsk, frame_length, mirror_enabled,
					      generic_l2_rx_frame, thread_context, &tx_time);
		thread_context->received_frames = received;
		pthread_mutex_unlock(&thread_context->xdp_data_mutex);

		workload_signal(thread_context, received);
	}

	return NULL;
}

struct thread_context *generic_l2_threads_create(void)
{
	struct traffic_class_config *l2_config;
	struct thread_context *thread_context;
	char thread_name[128];
	int ret;

	thread_context = calloc(1, sizeof(*thread_context));
	if (!thread_context)
		return NULL;

	if (!config_is_traffic_class_active("GenericL2"))
		goto out;

	thread_context->conf = l2_config = &app_config.classes[GENERICL2_FRAME_TYPE];
	thread_context->frame_type = GENERICL2_FRAME_TYPE;
	thread_context->traffic_class = stat_frame_type_to_string(GENERICL2_FRAME_TYPE);

	/* For XDP the frames are stored in a umem area. That memory is part of the socket. */
	if (!l2_config->xdp_enabled) {
		thread_context->packet_context = packet_init(l2_config->num_frames_per_cycle);
		if (!thread_context->packet_context) {
			fprintf(stderr, "Failed to allocate GenericL2 packet context!\n");
			goto err_packet;
		}

		thread_context->tx_frame_data =
			calloc(l2_config->num_frames_per_cycle, MAX_FRAME_SIZE);
		if (!thread_context->tx_frame_data) {
			fprintf(stderr, "Failed to allocate GenericL2TxFrameData\n");
			goto err_tx;
		}

		thread_context->rx_frame_data =
			calloc(l2_config->num_frames_per_cycle, MAX_FRAME_SIZE);
		if (!thread_context->rx_frame_data) {
			fprintf(stderr, "Failed to allocate GenericL2RxFrameData\n");
			goto err_rx;
		}
	}

	/* For XDP a AF_XDP socket is allocated. Otherwise a Linux raw socket is used. */
	if (l2_config->xdp_enabled) {
		thread_context->socket_fd = 0;
		thread_context->xsk = xdp_open_socket(
			l2_config->interface, app_config.application_xdp_program,
			l2_config->rx_queue, l2_config->xdp_skb_mode, l2_config->xdp_zc_mode,
			l2_config->xdp_wakeup_mode, l2_config->xdp_busy_poll_mode,
			l2_config->tx_time_enabled, l2_config->tx_hwtstamp_enabled);
		if (!thread_context->xsk) {
			fprintf(stderr, "Failed to create GenericL2 Xdp socket!\n");
			goto err_socket;
		}
	} else {
		thread_context->xsk = NULL;
		thread_context->socket_fd = create_generic_l2_socket();
		if (thread_context->socket_fd < 0) {
			fprintf(stderr, "Failed to create GenericL2 Socket!\n");
			goto err_socket;
		}
	}

	init_mutex(&thread_context->xdp_data_mutex);

	/* Same as above. For XDP the umem area is used. */
	if (l2_config->rx_mirror_enabled && !l2_config->xdp_enabled) {
		/* Per period the expectation is: GenericL2NumFramesPerCycle * MAX_FRAME */
		thread_context->mirror_buffer =
			ring_buffer_allocate(MAX_FRAME_SIZE * l2_config->num_frames_per_cycle);
		if (!thread_context->mirror_buffer) {
			fprintf(stderr, "Failed to allocate GenericL2 Mirror RingBuffer!\n");
			goto err_buffer;
		}
	}

	snprintf(thread_name, sizeof(thread_name), "%sTxThread", l2_config->name);

	ret = create_rt_thread(&thread_context->tx_task_id, thread_name,
			       l2_config->tx_thread_priority, l2_config->tx_thread_cpu,
			       l2_config->xdp_enabled ? generic_l2_xdp_tx_thread_routine
						      : generic_l2_tx_thread_routine,
			       thread_context);
	if (ret) {
		fprintf(stderr, "Failed to create GenericL2 Tx Thread!\n");
		goto err_thread;
	}

	snprintf(thread_name, sizeof(thread_name), "%sRxThread", l2_config->name);

	ret = create_rt_thread(&thread_context->rx_task_id, thread_name,
			       l2_config->rx_thread_priority, l2_config->rx_thread_cpu,
			       l2_config->xdp_enabled ? generic_l2_xdp_rx_thread_routine
						      : generic_l2_rx_thread_routine,
			       thread_context);
	if (ret) {
		fprintf(stderr, "Failed to create GenericL2 Rx Thread!\n");
		goto err_thread_rx;
	}

	/* Create workload thread for execution after network RX */
	if (l2_config->rx_workload_enabled) {
		thread_context->workload = calloc(1, sizeof(struct workload_config));
		if (!thread_context->workload) {
			fprintf(stderr, "Failed to allocate workload!\n");
			ret = -ENOMEM;
			goto err_thread_wl;
		}

		ret = workload_context_init(
			thread_context, l2_config->workload_file, l2_config->workload_function,
			l2_config->workload_arguments, l2_config->workload_setup_function,
			l2_config->workload_setup_arguments, thread_context->frame_type);
		if (ret) {
			fprintf(stderr, "Failed to create workload context!\n");
			goto err_thread_wl;
		}
		ret = create_rt_thread(
			&thread_context->workload->workload_task_id, l2_config->workload_function,
			l2_config->workload_thread_priority, l2_config->workload_thread_cpu,
			&workload_thread_routine, thread_context);
		if (ret) {
			fprintf(stderr, "Failed to create Rtc Workload Thread!\n");
			goto err_thread_wl;
		}
	}

	thread_context->meta_data_offset =
		get_meta_data_offset(GENERICL2_FRAME_TYPE, SECURITY_MODE_NONE);

out:
	return thread_context;

err_thread_wl:
	thread_context->stop = 1;
	free(thread_context->workload);
	pthread_join(thread_context->rx_task_id, NULL);
err_thread_rx:
	thread_context->stop = 1;
	pthread_join(thread_context->tx_task_id, NULL);
err_thread:
	ring_buffer_free(thread_context->mirror_buffer);
err_buffer:
	if (thread_context->socket_fd)
		close(thread_context->socket_fd);
	if (thread_context->xsk)
		xdp_close_socket(thread_context->xsk, l2_config->interface,
				 l2_config->xdp_skb_mode);
err_socket:
	free(thread_context->rx_frame_data);
err_rx:
	free(thread_context->tx_frame_data);
err_tx:
	packet_free(thread_context->packet_context);
err_packet:
	free(thread_context);
	return NULL;
}

void generic_l2_threads_free(struct thread_context *thread_context)
{
	struct traffic_class_config *l2_config;

	if (!thread_context)
		return;

	l2_config = thread_context->conf;

	ring_buffer_free(thread_context->mirror_buffer);

	packet_free(thread_context->packet_context);
	free(thread_context->tx_frame_data);
	free(thread_context->rx_frame_data);

	if (thread_context->socket_fd > 0)
		close(thread_context->socket_fd);

	if (thread_context->xsk)
		xdp_close_socket(thread_context->xsk, l2_config->interface,
				 l2_config->xdp_skb_mode);

	if (thread_context->workload && thread_context->workload->workload_task_id)
		workload_thread_free(thread_context);

	free(thread_context);
}

void generic_l2_threads_wait_for_finish(struct thread_context *thread_context)
{
	if (!thread_context)
		return;

	if (thread_context->workload && thread_context->workload->workload_task_id)
		pthread_join(thread_context->workload->workload_task_id, NULL);
	if (thread_context->rx_task_id)
		pthread_join(thread_context->rx_task_id, NULL);
	if (thread_context->tx_task_id)
		pthread_join(thread_context->tx_task_id, NULL);
}
