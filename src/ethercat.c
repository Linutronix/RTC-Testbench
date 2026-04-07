/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2026 acontis technologies GmbH
   Author Haithem Jebali <h.jebali@acontis.com>
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
void initialize_ethercat_frame(unsigned char *frame_data, size_t frame_length,
			       const unsigned char *source, const unsigned char *destination)
{
	struct ethhdr *eth;
	struct ethercat_header *ecat;
	size_t payload_offset;
	__u8 ethercat_header[ETHERCAT_HEADER_LEN] = {0x16, 0x10};
	/* E88A4 Length 0x16, Type ECAT (0x1) */ /*14-15*/

	__u8 ethercat_nop_cmd[20] = {
		0x00,
		/* Nope cmd */ /*16*/
		0x00,
		/* Index */ /*17*/
		0x00,
		0x00,
		/* Slave Address */ /*18-19*/
		0x00,
		0x00,
		/* Offset Address */ /*20-21*/
		0x08,
		0x00,
		/* Length - Last sub command */ /*22-23*/
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		/* Interrupt */ /*24-25*/
		0x00,
		0x00 /* Working Counter */ /*30-31*/
	};
	/* Initialize to zero */
	memset(frame_data, '\0', frame_length);

	/*
	 * EtherCAT Frame:
	 *   Destination
	 *   Source
	 *   Ether type: 88A4
	 *   Ecat frame Header: length + type
	 *   Ecat datagram(s)
	 */

	eth = (struct ethhdr *)frame_data;
	ecat = (struct ethercat_header *)(frame_data + sizeof(*eth));

	/* Ethernet header */
	memcpy(eth->h_dest, destination, ETH_ALEN);
	memcpy(eth->h_source, source, ETH_ALEN);
	eth->h_proto = htons(ETH_P_ETHERCAT);

	/* EtherCAT header */
	memcpy(&ecat->length, &ethercat_header[0], ETHERCAT_HEADER_LEN);

	/* Payload */
	payload_offset = sizeof(*eth) + sizeof(*ecat);
	memcpy(frame_data + payload_offset, &ethercat_nop_cmd[0], 20);
}

int receive_ethercat_frame(void *data, unsigned char *frame_data, size_t len)
{
	struct thread_context *thread_context = data;
	uint64_t tx_sw_timestamp, rx_sw_timestamp;
	struct timespec rx_time = {};
	// uint64_t sequence_counter;
	void *p = frame_data;
	struct ethhdr *eth;
	uint16_t proto;

	clock_gettime(app_config.application_clock_id, &rx_time);

	if (len < sizeof(struct ethhdr)) {
		log_message(LOG_LEVEL_WARNING, "%sRx: Too small frame received!\n",
			    thread_context->traffic_class);
		return -EINVAL;
	}

	eth = p;
	proto = eth->h_proto;
	p += sizeof(*eth);

	if (proto != htons(ETH_P_ETHERCAT)) {
		log_message(LOG_LEVEL_WARNING, "%sRx: Not an EtherCAT frame received!\n",
			    thread_context->traffic_class);
		return -EINVAL;
	}

	/* check that the slave processed the frame */
	if (eth->h_source[0] == thread_context->source[0]) {
		log_message(LOG_LEVEL_WARNING, "%sRx: the slave did not process the frame!\n",
			    thread_context->traffic_class);
		return -EINVAL;
	}

	memcpy(&tx_sw_timestamp, &frame_data[ECAT_TX_TIMESTAMP_OFF], sizeof(uint64_t));

	rx_sw_timestamp = ts_to_ns(&rx_time);
	stat_frame_received(thread_context->frame_type, thread_context->rx_sequence_counter, false,
			    false, false, tx_sw_timestamp, 0, rx_sw_timestamp);

	thread_context->rx_sequence_counter++;

	return 0;
}
