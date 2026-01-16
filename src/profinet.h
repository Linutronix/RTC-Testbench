/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2020-2026 Linutronix GmbH
 */

#include "security.h"

/*
 * This function initializes an PROFINET Ethernet frame. The Ethernet header, PROFINET header and
 * payload is initialized. The sequenceCounter is set to zero.
 *
 * In case the SecurityMode is AE or AO, the PROFINET Ethernet frames will contain the
 * SecurityHeader after the FrameID.
 */
void initialize_profinet_frame(enum security_mode mode, unsigned char *frame_data,
			       size_t frame_length, const unsigned char *source,
			       const unsigned char *destination, const char *payload_pattern,
			       size_t payload_pattern_length, uint16_t vlan_tci, uint16_t frame_id);

/*
 * This function receives a Profinet frame. It performs all required tests such as checking sequence
 * counters, payload, checksums, etc. This is used for TSN, RTC and RTA as well as by packet and xdp
 * code.
 */
int receive_profinet_frame(void *data, unsigned char *frame_data, size_t len);
