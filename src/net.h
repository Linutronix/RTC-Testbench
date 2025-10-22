/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2020-2025 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#ifndef _NET_H_
#define _NET_H_

#include <stddef.h>

#include <sys/socket.h>

#include "net_def.h"

int create_tsn_high_socket(void);
int create_tsn_low_socket(void);
int create_rtc_socket(void);
int create_rta_socket(void);
int create_dcp_socket(void);
int create_lldp_socket(void);
int create_generic_l2_socket(void);
int create_udp_socket(const char *udp_destination, const char *udp_source, const char *udp_port,
		      int socket_priority, struct sockaddr_storage *destination);
int create_udp_cl_socket(const char *udp_destination, const char *udp_port,
			 struct sockaddr_storage *destination);
int get_interface_mac_address(const char *if_name, unsigned char *mac, size_t len);
int get_interface_link_speed(const char *if_name, uint32_t *speed);

#endif /* _NET_H_ */
