/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2026 acontis technologies GmbH
 * Author Haithem Jebali <h.jebali@acontis.com>
 */

#ifndef ETHERCAT_H
#define ETHERCAT_H

struct thread_context;

/*
 * This function initializes an EtherCAT Ethernet frame. The Ethernet header, EtherCAT header and
 * payload is initialized.
 */
void initialize_ethercat_frame(struct thread_context *ctx, unsigned char *frame_data,
			       size_t frame_length, const unsigned char *source,
			       const unsigned char *destination);

/*
 * This function receives an EtherCAT frame. It performs all required tests such as checking
 * sequence counters, payload, checksums, etc. This is used for GenericL2 as well as by packet and
 * xdp code.
 */
int receive_ethercat_frame(void *data, unsigned char *frame_data, size_t len);

#endif /* ETHERCAT_H */
