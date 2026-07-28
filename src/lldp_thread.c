// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2020-2026 Linutronix GmbH
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
#include "tc.h"
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
	set_mirror_tx_timestamp_est(meta);
}

static void lldp_initialize_frame(struct thread_context *thread_context, unsigned char *frame_data,
				  size_t frame_length, const unsigned char *source,
				  const unsigned char *destination)
{
	const struct traffic_class_config *lldp_config = thread_context->conf;
	struct reference_meta_data *meta;
	size_t payload_offset;
	struct ethhdr *eth;

	/* Initialize to zero */
	memset(frame_data, '\0', frame_length);

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

	return 0;
}

int lldp_threads_create(struct thread_context *ctx)
{
	struct traffic_class_config *conf;
	int ret;

	if (!config_is_tc_active(LLDP_FRAME_TYPE))
		return 0;

	ctx->conf = conf = &app_config.classes[LLDP_FRAME_TYPE];
	ctx->frame_type = LLDP_FRAME_TYPE;
	ctx->traffic_class = stat_frame_type_to_string(LLDP_FRAME_TYPE);
	ctx->frame_id = 0;

	ctx->desc = calloc(1, sizeof(*ctx->desc));
	if (!ctx->desc) {
		fprintf(stderr, "Failed to allocate %s TC description!\n", ctx->traffic_class);
		return -ENOMEM;
	}

	ctx->desc->tx_model = TC_TX_BURST;
	ctx->desc->ops.initialize_frame = lldp_initialize_frame;
	ctx->desc->ops.receive_frame = lldp_rx_frame;
	ctx->desc->ops.create_socket = create_lldp_socket;
	ctx->desc->ops.tx_thread = tc_tx_thread;
	ctx->desc->ops.rx_thread = tc_rx_thread;

	ret = tc_threads_create(ctx);
	if (ret)
		free(ctx->desc);

	return ret;
}

void lldp_threads_free(struct thread_context *thread_context)
{
	tc_threads_free(thread_context);
}

void lldp_threads_wait_for_finish(struct thread_context *thread_context)
{
	tc_threads_wait_for_finish(thread_context);
}
