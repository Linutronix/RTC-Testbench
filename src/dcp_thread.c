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
#include <linux/if_vlan.h>

#include "config.h"
#include "dcp_thread.h"
#include "log.h"
#include "net.h"
#include "packet.h"
#include "profinet.h"
#include "security.h"
#include "stat.h"
#include "tc.h"
#include "thread.h"
#include "utils.h"

static void dcp_initialize_frame(struct thread_context *thread_context, unsigned char *frame_data,
				 size_t frame_length, const unsigned char *source,
				 const unsigned char *destination)
{
	const struct traffic_class_config *conf = thread_context->conf;

	initialize_profinet_frame(SECURITY_MODE_NONE, frame_data, frame_length, source, destination,
				  conf->payload_pattern, conf->payload_pattern_length,
				  conf->vid | conf->pcp << VLAN_PCP_SHIFT, DCP_FRAMEID);
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
	set_mirror_tx_timestamp_est(&rt->meta_data);
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

	return 0;
}

int dcp_threads_create(struct thread_context *ctx)
{
	struct traffic_class_config *conf;
	int ret;

	if (!config_is_tc_active(DCP_FRAME_TYPE))
		return 0;

	ctx->conf = conf = &app_config.classes[DCP_FRAME_TYPE];
	ctx->frame_type = DCP_FRAME_TYPE;
	ctx->traffic_class = stat_frame_type_to_string(DCP_FRAME_TYPE);
	ctx->frame_id = DCP_FRAMEID;

	ctx->desc = calloc(1, sizeof(*ctx->desc));
	if (!ctx->desc) {
		fprintf(stderr, "Failed to allocate %s TC description!\n", ctx->traffic_class);
		return -ENOMEM;
	}

	ctx->desc->tx_model = TC_TX_BURST;
	ctx->desc->ops.initialize_frame = dcp_initialize_frame;
	ctx->desc->ops.receive_frame = dcp_rx_frame;
	ctx->desc->ops.create_socket = create_dcp_socket;
	ctx->desc->ops.tx_thread = tc_tx_thread;
	ctx->desc->ops.rx_thread = tc_rx_thread;

	ret = tc_threads_create(ctx);
	if (ret)
		free(ctx->desc);

	return ret;
}

void dcp_threads_free(struct thread_context *thread_context)
{
	tc_threads_free(thread_context);
}

void dcp_threads_wait_for_finish(struct thread_context *thread_context)
{
	tc_threads_wait_for_finish(thread_context);
}
