// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2020-2026 Linutronix GmbH
 */

#include <pthread.h>
#include <string.h>

#include <arpa/inet.h>

#include "log.h"
#include "net_def.h"
#include "ring_buffer.h"
#include "thread.h"
#include "utils.h"
#include "xdp.h"

static void initialize_secure_profinet_frame(enum security_mode mode, unsigned char *frame_data,
					     size_t frame_length, const unsigned char *source,
					     const unsigned char *destination,
					     const char *payload_pattern,
					     size_t payload_pattern_length, uint16_t vlan_tci,
					     uint16_t frame_id)
{
	struct profinet_secure_header *rt;
	struct vlan_ethernet_header *eth;
	uint16_t security_length;
	size_t payload_offset;

	/* Initialize to zero */
	memset(frame_data, '\0', frame_length);

	/*
	 * Profinet Frame:
	 *   Destination
	 *   Source
	 *   VLAN tag: tpid 8100, id 0x00/0x101/102, dei 0, prio 6/5/4/3/2
	 *   Ether type: 8892
	 *   Frame id: TSN, RTC, RTA, DCP
	 *   SecurityHeader
	 *   Cycle counter
	 *   Payload
	 *   Padding to maxFrame - Checksum
	 *   security_checksum
	 */

	eth = (struct vlan_ethernet_header *)frame_data;
	rt = (struct profinet_secure_header *)(frame_data + sizeof(*eth));

	/* Ethernet header */
	memcpy(eth->destination, destination, ETH_ALEN);
	memcpy(eth->source, source, ETH_ALEN);

	/* VLAN Header */
	eth->vlan_proto = htons(ETH_P_8021Q);
	eth->vlantci = htons(vlan_tci);
	eth->vlan_encapsulated_proto = htons(ETH_P_PROFINET_RT);

	/* Profinet Secure header */
	security_length = frame_length - sizeof(*eth) - sizeof(struct security_checksum);
	rt->frame_id = htons(frame_id);
	rt->security_meta_data.security_information = mode == SECURITY_MODE_AO ? 0x00 : 0x01;
	rt->security_meta_data.security_length = htobe16(security_length);
	rt->meta_data.frame_counter = 0;
	rt->meta_data.cycle_counter = 0;

	/* Payload */
	payload_offset = sizeof(*eth) + sizeof(*rt);
	memcpy(frame_data + payload_offset, payload_pattern, payload_pattern_length);

	/* security_checksum is set to zero and calculated for each frame on Tx */
}

static void initialize_rt_profinet_frame(unsigned char *frame_data, size_t frame_length,
					 const unsigned char *source,
					 const unsigned char *destination,
					 const char *payload_pattern, size_t payload_pattern_length,
					 uint16_t vlan_tci, uint16_t frame_id)
{
	struct vlan_ethernet_header *eth;
	struct profinet_rt_header *rt;
	size_t payload_offset;

	/* Initialize to zero */
	memset(frame_data, '\0', frame_length);

	/*
	 * Profinet Frame:
	 *   Destination
	 *   Source
	 *   VLAN tag: tpid 8100, id 0x00/0x101/102, dei 0, prio 6/5/4/3/2
	 *   Ether type: 8892
	 *   Frame id: TSN, RTC, RTA, DCP
	 *   Cycle counter
	 *   Payload
	 *   Padding to maxFrame
	 */

	eth = (struct vlan_ethernet_header *)frame_data;
	rt = (struct profinet_rt_header *)(frame_data + sizeof(*eth));

	/* Ethernet header */
	memcpy(eth->destination, destination, ETH_ALEN);
	memcpy(eth->source, source, ETH_ALEN);

	/* VLAN Header */
	eth->vlan_proto = htons(ETH_P_8021Q);
	eth->vlantci = htons(vlan_tci);
	eth->vlan_encapsulated_proto = htons(ETH_P_PROFINET_RT);

	/* Profinet RT header */
	rt->frame_id = htons(frame_id);
	rt->meta_data.frame_counter = 0;
	rt->meta_data.cycle_counter = 0;

	/* Payload */
	payload_offset = sizeof(*eth) + sizeof(*rt);
	memcpy(frame_data + payload_offset, payload_pattern, payload_pattern_length);
}

void initialize_profinet_frame(enum security_mode mode, unsigned char *frame_data,
			       size_t frame_length, const unsigned char *source,
			       const unsigned char *destination, const char *payload_pattern,
			       size_t payload_pattern_length, uint16_t vlan_tci, uint16_t frame_id)
{
	switch (mode) {
	case SECURITY_MODE_NONE:
		initialize_rt_profinet_frame(frame_data, frame_length, source, destination,
					     payload_pattern, payload_pattern_length, vlan_tci,
					     frame_id);
		break;
	case SECURITY_MODE_AE:
	case SECURITY_MODE_AO:
		initialize_secure_profinet_frame(mode, frame_data, frame_length, source,
						 destination, payload_pattern,
						 payload_pattern_length, vlan_tci, frame_id);
		break;
	}
}

int receive_profinet_frame(void *data, unsigned char *frame_data, size_t len)
{
	struct thread_context *thread_context = data;
	const struct traffic_class_config *class_config = thread_context->conf;
	const unsigned char *expected_pattern =
		(const unsigned char *)class_config->payload_pattern;
	struct security_context *security_context = thread_context->rx_security_context;
	const size_t expected_pattern_length = class_config->payload_pattern_length;
	const bool mirror_enabled = class_config->rx_mirror_enabled;
	const bool ignore_rx_errors = class_config->ignore_rx_errors;
	size_t expected_frame_length = class_config->frame_length;
	uint64_t tx_timestamp, rx_hw_timestamp, rx_sw_timestamp;
	bool out_of_order, payload_mismatch, frame_id_mismatch;
	unsigned char plaintext[MAX_FRAME_SIZE];
	unsigned char new_frame[MAX_FRAME_SIZE];
	struct profinet_secure_header *srt;
	struct profinet_rt_header *rt;
	uint64_t sequence_counter;
	bool vlan_tag_missing;
	void *p = frame_data;
	struct ethhdr *eth;
	uint16_t frame_id;
	uint16_t proto;

	if (len < sizeof(struct vlan_ethernet_header)) {
		log_message(LOG_LEVEL_WARNING, "%sRx: Too small frame received!\n",
			    thread_context->traffic_class);
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

	if (proto != htons(ETH_P_PROFINET_RT)) {
		log_message(LOG_LEVEL_WARNING, "%sRx: Not a Profinet frame received!\n",
			    thread_context->traffic_class);
		return -EINVAL;
	}

	/* Check frame length: VLAN tag might be stripped or not. Check it. */
	if (len != expected_frame_length) {
		log_message(LOG_LEVEL_WARNING, "%sRx: Frame with wrong length received!\n",
			    thread_context->traffic_class);
		return -EINVAL;
	}

	/* Check cycle counter, frame id range and payload. */
	if (class_config->security_mode == SECURITY_MODE_NONE) {
		rt = p;
		p += sizeof(*rt);

		frame_id = be16toh(rt->frame_id);
		sequence_counter = meta_data_to_sequence_counter(
			&rt->meta_data, class_config->num_frames_per_cycle);

		tx_timestamp = meta_data_to_tx_timestamp(&rt->meta_data);
		set_mirror_tx_timestamp(&rt->meta_data);

	} else if (class_config->security_mode == SECURITY_MODE_AO) {

		unsigned char *begin_of_security_checksum;
		unsigned char *begin_of_aad_data;
		size_t size_of_eth_header;
		size_t size_of_aad_data;
		struct security_iv iv;
		int ret;

		srt = p;
		p += sizeof(*srt);

		frame_id = be16toh(srt->frame_id);
		sequence_counter = meta_data_to_sequence_counter(
			&srt->meta_data, class_config->num_frames_per_cycle);

		tx_timestamp = meta_data_to_tx_timestamp(&srt->meta_data);

		/* Authenticate received Profinet Frame */
		size_of_eth_header = vlan_tag_missing ? sizeof(struct ethhdr)
						      : sizeof(struct vlan_ethernet_header);

		begin_of_aad_data = frame_data + size_of_eth_header;
		size_of_aad_data = len - size_of_eth_header - sizeof(struct security_checksum);
		begin_of_security_checksum = frame_data + (len - sizeof(struct security_checksum));

		prepare_iv((const unsigned char *)class_config->security_iv_prefix,
			   sequence_counter, &iv);

		ret = security_decrypt(security_context, NULL, 0, begin_of_aad_data,
				       size_of_aad_data, begin_of_security_checksum,
				       (unsigned char *)&iv, NULL);
		if (ret)
			log_message(LOG_LEVEL_WARNING,
				    "%sRx: frame[%" PRIu64 "] Not authentificated\n",
				    thread_context->traffic_class, sequence_counter);

		set_mirror_tx_timestamp(&srt->meta_data);

		security_encrypt(security_context, NULL, 0, begin_of_aad_data, size_of_aad_data,
				 (unsigned char *)&iv, NULL, begin_of_security_checksum);

	} else {
		unsigned char *begin_of_security_checksum;
		unsigned char *begin_of_ciphertext;
		unsigned char *begin_of_aad_data;
		size_t size_of_ciphertext;
		size_t size_of_eth_header;
		size_t size_of_aad_data;
		struct security_iv iv;
		int ret;

		srt = p;

		frame_id = be16toh(srt->frame_id);
		sequence_counter = meta_data_to_sequence_counter(
			&srt->meta_data, class_config->num_frames_per_cycle);

		tx_timestamp = meta_data_to_tx_timestamp(&srt->meta_data);

		/* Authenticate received Profinet Frame */
		size_of_eth_header = vlan_tag_missing ? sizeof(struct ethhdr)
						      : sizeof(struct vlan_ethernet_header);

		begin_of_aad_data = frame_data + size_of_eth_header;
		size_of_aad_data = sizeof(*srt);
		begin_of_security_checksum = frame_data + (len - sizeof(struct security_checksum));
		begin_of_ciphertext = frame_data + size_of_eth_header + sizeof(*srt);
		size_of_ciphertext = len - sizeof(struct vlan_ethernet_header) -
				     sizeof(struct profinet_secure_header) -
				     sizeof(struct security_checksum);

		prepare_iv((const unsigned char *)class_config->security_iv_prefix,
			   sequence_counter, &iv);

		ret = security_decrypt(security_context, begin_of_ciphertext, size_of_ciphertext,
				       begin_of_aad_data, size_of_aad_data,
				       begin_of_security_checksum, (unsigned char *)&iv, plaintext);
		if (ret)
			log_message(LOG_LEVEL_WARNING,
				    "%sRx: frame[%" PRIu64 "] Not authentificated and decrypted\n",
				    thread_context->traffic_class, sequence_counter);

		/* plaintext points to the decrypted payload */
		p = plaintext;

		set_mirror_tx_timestamp(&srt->meta_data);

		security_encrypt(security_context, thread_context->payload_pattern,
				 thread_context->payload_pattern_length, begin_of_aad_data,
				 size_of_aad_data, (unsigned char *)&iv, begin_of_ciphertext,
				 begin_of_security_checksum);
	}

	xdp_get_timestamp_metadata(frame_data, &rx_hw_timestamp, &rx_sw_timestamp);
	out_of_order = sequence_counter != thread_context->rx_sequence_counter;
	payload_mismatch = memcmp(p, expected_pattern, expected_pattern_length);
	frame_id_mismatch = frame_id != thread_context->frame_id;

	stat_frame_received(thread_context->frame_type, sequence_counter, out_of_order,
			    payload_mismatch, frame_id_mismatch, tx_timestamp, rx_hw_timestamp,
			    rx_sw_timestamp);

	if (frame_id_mismatch)
		log_message(
			LOG_LEVEL_WARNING, "%sRx: frame[%" PRIu64 "] FrameId mismatch: 0x%4x!\n",
			thread_context->traffic_class, sequence_counter, thread_context->frame_id);

	if (out_of_order) {
		if (!ignore_rx_errors)
			log_message(LOG_LEVEL_WARNING,
				    "%sRx: frame[%" PRIu64 "] SequenceCounter mismatch: %" PRIu64
				    "!\n",
				    thread_context->traffic_class, sequence_counter,
				    thread_context->rx_sequence_counter);
		thread_context->rx_sequence_counter++;
	}

	if (payload_mismatch)
		log_message(LOG_LEVEL_WARNING,
			    "%sRx: frame[%" PRIu64 "] Payload Pattern mismatch!\n",
			    thread_context->traffic_class, sequence_counter);

	thread_context->rx_sequence_counter++;

	/*
	 * If mirror enabled, assemble and store the frame for Tx later.
	 *
	 * In case of XDP the Rx umem area will be reused for Tx.
	 */
	if (!mirror_enabled)
		return 0;

	if (class_config->xdp_enabled) {
		/* Re-add vlan tag */
		if (vlan_tag_missing)
			insert_vlan_tag(frame_data, len, ETH_P_PROFINET_RT,
					class_config->vid | class_config->pcp << VLAN_PCP_SHIFT);

		/* Swap mac addresses inline */
		swap_mac_addresses(frame_data, len);
	} else {
		/* Build new frame for Tx with VLAN info. */
		build_vlan_frame_from_rx(frame_data, len, new_frame, sizeof(new_frame),
					 ETH_P_PROFINET_RT,
					 class_config->vid | class_config->pcp << VLAN_PCP_SHIFT);

		/* Store the new frame. */
		ring_buffer_add(thread_context->mirror_buffer, new_frame,
				len + sizeof(struct vlan_header));
	}

	/* RTA is a burst traffic class and needs to update num_frames_available */
	if (thread_context->frame_type == RTA_FRAME_TYPE) {
		pthread_mutex_lock(&thread_context->data_mutex);
		thread_context->num_frames_available++;
		pthread_mutex_unlock(&thread_context->data_mutex);
	}

	return 0;
}
