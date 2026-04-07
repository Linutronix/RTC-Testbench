/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2026 acontis technologies GmbH
   Author Haithem Jebali <h.jebali@acontis.com>
 */

/*
 * This function initializes an EtherCAT Ethernet frame. The Ethernet header, EtherCAT header and
 * payload is initialized. The sequenceCounter is set to zero.
 */
void initialize_ethercat_frame(unsigned char *frame_data, size_t frame_length,
			       const unsigned char *source, const unsigned char *destination);

/*
 * This function receives an EtherCAT frame. It performs all required tests such as checking
 * sequence counters, payload, checksums, etc. This is used for TSN, RTC and RTA as well as by
 * packet and xdp code.
 */
int receive_ethercat_frame(void *data, unsigned char *frame_data, size_t len);
