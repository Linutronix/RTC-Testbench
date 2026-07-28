// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2022-2026 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>

#include "app_config.h"

#include "config.h"
#include "ethercat.h"
#include "layer2_thread.h"
#include "log.h"
#include "net.h"
#include "stat.h"
#include "tc.h"
#include "thread.h"
#include "utils.h"
#include "workload.h"
#include "xdp.h"

static void generic_l2_initialize_frame(struct thread_context *thread_context,
					unsigned char *frame_data, size_t frame_length,
					const unsigned char *source,
					const unsigned char *destination)
{
	const struct traffic_class_config *l2_config = thread_context->conf;
	struct vlan_ethernet_header *eth;
	struct generic_l2_header *l2;
	size_t payload_offset;

	/* Initialize to zero */
	memset(frame_data, '\0', frame_length);

	/*
	 * GenericL2Frame:
	 *   Destination
	 *   Source
	 *   VLAN tag
	 *   Ether type
	 *   Cycle counter
	 *   Payload
	 *   Padding to maxFrame
	 */

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
	set_mirror_tx_timestamp_est(&l2->meta_data);

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

int generic_l2_threads_create(struct thread_context *ctx)
{
	struct traffic_class_config *conf;
	int ret;

	if (!config_is_tc_active(GENERICL2_FRAME_TYPE))
		return 0;

	ctx->conf = conf = &app_config.classes[GENERICL2_FRAME_TYPE];
	ctx->frame_type = GENERICL2_FRAME_TYPE;
	ctx->traffic_class = stat_frame_type_to_string(GENERICL2_FRAME_TYPE);
	ctx->frame_id = 0;

	ctx->desc = calloc(1, sizeof(*ctx->desc));
	if (!ctx->desc) {
		fprintf(stderr, "Failed to allocate %s TC description!\n", ctx->traffic_class);
		return -ENOMEM;
	}

	ctx->desc->tx_model = TC_TX_STANDALONE;

	if (conf->protocol_type == ETHERCAT_PROTOCOL_TYPE) {
		ctx->desc->ops.initialize_frame = initialize_ethercat_frame;
		ctx->desc->ops.receive_frame = receive_ethercat_frame;
		ctx->desc->ops.create_socket = create_ethercat_socket;
	} else {
		ctx->desc->ops.initialize_frame = generic_l2_initialize_frame;
		ctx->desc->ops.receive_frame = generic_l2_rx_frame;
		ctx->desc->ops.create_socket = create_generic_l2_socket;
	}

	if (conf->xdp_enabled) {
		ctx->desc->ops.tx_thread = tc_xdp_tx_thread;
		ctx->desc->ops.rx_thread = tc_xdp_rx_thread;
	} else {
		ctx->desc->ops.tx_thread = tc_tx_thread;
		ctx->desc->ops.rx_thread = tc_rx_thread;
	}

	ret = tc_threads_create(ctx);
	if (ret)
		free(ctx->desc);

	return ret;
}

void generic_l2_threads_free(struct thread_context *thread_context)
{
	tc_threads_free(thread_context);
}

void generic_l2_threads_wait_for_finish(struct thread_context *thread_context)
{
	tc_threads_wait_for_finish(thread_context);
}
