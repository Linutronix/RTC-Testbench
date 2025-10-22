// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2020-2025 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <linux/ethtool.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/net.h>
#include <linux/net_tstamp.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "config.h"
#include "net.h"
#include "stat.h"
#include "utils.h"

/*
 * Filter for Profinet TSN High Frames:
 *   ldh [12]
 *   jne #0x8892, drop
 *   ld vlan_tci
 *   jne #VlanTCI, drop
 *   ldh [14]
 *   jlt #0x0100, drop
 *   jgt #0x01ff, drop
 *   ret #-1
 *   drop: ret #0
 */
static struct sock_filter tsn_high_frame_filter[] = {
	{0x28, 0, 0, 0x0000000c}, {0x15, 0, 6, 0x00008892}, {0x20, 0, 0, 0xfffff02c},
	{0x15, 0, 4, 0x00001234}, {0x28, 0, 0, 0x0000000e}, {0x35, 0, 2, 0x00000100},
	{0x25, 1, 0, 0x000001ff}, {0x06, 0, 0, 0xffffffff}, {0x06, 0, 0, 0000000000},
};

/*
 * Filter for Profinet TSN Low Frames:
 *   ldh [12]
 *   jne #0x8892, drop
 *   ld vlan_tci
 *   jne #VlanTCI, drop
 *   ldh [14]
 *   jlt #0x0200, drop
 *   jgt #0x03ff, drop
 *   ret #-1
 *   drop: ret #0
 */
static struct sock_filter tsn_low_frame_filter[] = {
	{0x28, 0, 0, 0x0000000c}, {0x15, 0, 6, 0x00008892}, {0x20, 0, 0, 0xfffff02c},
	{0x15, 0, 4, 0x00001234}, {0x28, 0, 0, 0x0000000e}, {0x35, 0, 2, 0x00000200},
	{0x25, 1, 0, 0x000003ff}, {0x06, 0, 0, 0xffffffff}, {0x06, 0, 0, 0000000000},
};

/*
 * Filter for Profinet RTC Frames:
 *   ldh [12]
 *   jne #0x8892, drop
 *   ld vlan_tci
 *   jne #VlanTCI, drop
 *   ldh [14]
 *   jlt #0x8000, drop
 *   jgt #0xbbff, drop
 *   ret #-1
 *   drop: ret #0
 */
static struct sock_filter rtc_frame_filter[] = {
	{0x28, 0, 0, 0x0000000c}, {0x15, 0, 6, 0x00008892}, {0x20, 0, 0, 0xfffff02c},
	{0x15, 0, 4, 0x00001234}, {0x28, 0, 0, 0x0000000e}, {0x35, 0, 2, 0x00008000},
	{0x25, 1, 0, 0x0000bbff}, {0x06, 0, 0, 0xffffffff}, {0x06, 0, 0, 0000000000},
};

/*
 * Filter for Profinet RTA Frames:
 *   ldh [12]
 *   jne #0x8892, drop
 *   ld vlan_tci
 *   jne #VlanTCI, drop
 *   ldh [14]
 *   jlt #0xfc01, drop
 *   jgt #0xfc02, drop
 *   ret #-1
 *   drop: ret #0
 */
static struct sock_filter rta_frame_filter[] = {
	{0x28, 0, 0, 0x0000000c}, {0x15, 0, 6, 0x00008892}, {0x20, 0, 0, 0xfffff02c},
	{0x15, 0, 4, 0x00001234}, {0x28, 0, 0, 0x0000000e}, {0x35, 0, 2, 0x0000fc01},
	{0x25, 1, 0, 0x0000fc02}, {0x06, 0, 0, 0xffffffff}, {0x06, 0, 0, 0000000000},
};

/*
 * Filter for Profinet DCP Frames:
 *   ldh [12]
 *   jne #0x8892, drop
 *   ld vlan_tci
 *   jne #VlanTCI, drop
 *   ldh [14]
 *   jlt #0xfefe, drop
 *   jgt #0xfeff, drop
 *   ret #-1
 *   drop: ret #0
 */
static struct sock_filter dcp_frame_filter[] = {
	{0x28, 0, 0, 0x0000000c}, {0x15, 0, 6, 0x00008892}, {0x20, 0, 0, 0xfffff02c},
	{0x15, 0, 4, 0x00001234}, {0x28, 0, 0, 0x0000000e}, {0x35, 0, 2, 0x0000fefe},
	{0x25, 1, 0, 0x0000feff}, {0x06, 0, 0, 0xffffffff}, {0x06, 0, 0, 0000000000},
};

/*
 * Filter for LLDP Frames:
 *   ldh [12]
 *   jne #0x88cc, drop
 *   ret #-1
 *   drop: ret #0
 */
static struct sock_filter lldp_frame_filter[] = {
	{0x28, 0, 0, 0x0000000c},
	{0x15, 0, 1, 0x000088cc},
	{0x06, 0, 0, 0xffffffff},
	{0x06, 0, 0, 0000000000},
};

/*
 * Filter for Generic L2 Frames:
 *   ldh [12]
 *   jne #EtherType, drop
 *   ld vlan_tci
 *   jne #VlanTCI, drop
 *   ret #-1
 *   drop: ret #0
 */
static struct sock_filter generic_l2_frame_filter[] = {
	{0x28, 0, 0, 0x0000000c}, {0x15, 0, 3, 0x00001234}, {0x20, 0, 0, 0xfffff02c},
	{0x15, 0, 1, 0x00004321}, {0x06, 0, 0, 0xffffffff}, {0x06, 0, 0, 0000000000},
};

static int set_promiscuous_mode(int socket, int interface)
{
	struct packet_mreq mreq;
	int ret;

	mreq.mr_ifindex = interface;
	mreq.mr_type = PACKET_MR_PROMISC;
	mreq.mr_alen = 0;

	ret = setsockopt(socket, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
	if (ret) {
		perror("setsockopt() failed");
		return -errno;
	}

	return 0;
}

static int mark_socket_non_blocking(int socket_fd)
{
	int ret;

	ret = fcntl(socket_fd, F_GETFL);
	if (ret == -1) {
		perror("fcntl() failed");
		return -errno;
	}

	ret = fcntl(socket_fd, F_SETFL, ret | O_NONBLOCK);
	if (ret == -1) {
		perror("fcntl() failed");
		return -errno;
	}

	return 0;
}

static int create_raw_socket(const char *if_name, int socket_priority)
{
	struct sockaddr_ll address = {0};
	int socket_fd, interface, ret;

	socket_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (socket_fd < 0) {
		perror("socket() failed");
		goto err_socket;
	}

	interface = if_nametoindex(if_name);
	if (!interface) {
		perror("ioctl() failed");
		goto err_index;
	}

	address.sll_ifindex = interface;
	address.sll_family = AF_PACKET;
	address.sll_protocol = htons(ETH_P_ALL);

	ret = bind(socket_fd, (struct sockaddr *)&address, sizeof(address));
	if (ret < 0) {
		perror("bind() failed");
		goto err_index;
	}

	ret = setsockopt(socket_fd, SOL_SOCKET, SO_BINDTODEVICE, if_name, strlen(if_name));
	if (ret < 0) {
		perror("setsockopt() failed");
		goto err_index;
	}

	ret = setsockopt(socket_fd, SOL_SOCKET, SO_PRIORITY, &socket_priority,
			 sizeof(socket_priority));
	if (ret < 0) {
		perror("setsockopt() failed");
		goto err_index;
	}

	ret = set_promiscuous_mode(socket_fd, interface);
	if (ret)
		goto err_index;

	return socket_fd;

err_index:
	close(socket_fd);
err_socket:
	return -errno;
}

int get_interface_mac_address(const char *if_name, unsigned char *mac, size_t len)
{
	struct ifreq ifreq = {0};
	int socket_fd, ret;

	if (len < ETH_ALEN)
		return -EINVAL;

	strncpy(ifreq.ifr_name, if_name, sizeof(ifreq.ifr_name) - 1);

	socket_fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (socket_fd < 0) {
		perror("socket() failed");
		return -errno;
	}

	ret = ioctl(socket_fd, SIOCGIFHWADDR, &ifreq);
	close(socket_fd);
	if (ret < 0) {
		perror("ioctl() failed");
		return -errno;
	}

	memcpy(mac, ifreq.ifr_hwaddr.sa_data, ETH_ALEN);

	return 0;
}

int get_interface_link_speed(const char *if_name, uint32_t *speed)
{
	struct ifreq ifreq = {0};
	struct ethtool_cmd e_data;
	int socket_fd, ret;

	if (!speed)
		return -EINVAL;

	strncpy(ifreq.ifr_name, if_name, sizeof(ifreq.ifr_name) - 1);
	ifreq.ifr_data = (char *)&e_data;

	socket_fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (socket_fd < 0) {
		perror("socket() failed");
		return -errno;
	}

	e_data.cmd = ETHTOOL_GSET;

	ret = ioctl(socket_fd, SIOCETHTOOL, &ifreq);
	close(socket_fd);
	if (ret < 0) {
		perror("ioctl() failed");
		return -errno;
	}

	*speed = ethtool_cmd_speed(&e_data);

	return 0;
}

int create_tsn_high_socket(void)
{
	const struct sock_fprog tsn_high_filter_program = {.len = ARRAY_SIZE(tsn_high_frame_filter),
							   .filter = tsn_high_frame_filter};
	struct sock_txtime sk_txtime;
	int socket_fd, ret;

	socket_fd = create_raw_socket(app_config.classes[TSN_HIGH_FRAME_TYPE].interface,
				      app_config.classes[TSN_HIGH_FRAME_TYPE].socket_priority);
	if (socket_fd < 0) {
		fprintf(stderr, "Failed to create RAW socket for Profinet TSN High Frames!\n");
		return socket_fd;
	}

	/* Adjust filter: VLAN TCI */
	tsn_high_frame_filter[3].k = app_config.classes[TSN_HIGH_FRAME_TYPE].vid |
				     app_config.classes[TSN_HIGH_FRAME_TYPE].pcp << VLAN_PCP_SHIFT;

	ret = setsockopt(socket_fd, SOL_SOCKET, SO_ATTACH_FILTER, &tsn_high_filter_program,
			 sizeof(tsn_high_filter_program));
	if (ret < 0) {
		perror("setsockopt() failed");
		goto err_filter;
	}

	/* Mark socket as non-blocking */
	ret = mark_socket_non_blocking(socket_fd);
	if (ret) {
		fprintf(stderr, "Failed to mark TSN High socket as non-blocking!\n");
		goto err_filter;
	}

	/* Enable SO_TXTIME */
	if (!app_config.classes[TSN_HIGH_FRAME_TYPE].tx_time_enabled)
		goto out;

	sk_txtime.clockid = CLOCK_TAI; /* For hardware offload CLOCK_TAI is mandatory */
	sk_txtime.flags = 1 << 1;      /* Enable error reporting */
	ret = setsockopt(socket_fd, SOL_SOCKET, SO_TXTIME, &sk_txtime, sizeof(sk_txtime));
	if (ret) {
		perror("setsockopt() failed");
		goto err_filter;
	}

out:
	return socket_fd;

err_filter:
	close(socket_fd);
	return -errno;
}

int create_tsn_low_socket(void)
{
	const struct sock_fprog tsn_low_filter_program = {.len = ARRAY_SIZE(tsn_low_frame_filter),
							  .filter = tsn_low_frame_filter};
	struct sock_txtime sk_txtime;
	int socket_fd, ret;

	socket_fd = create_raw_socket(app_config.classes[TSN_LOW_FRAME_TYPE].interface,
				      app_config.classes[TSN_LOW_FRAME_TYPE].socket_priority);
	if (socket_fd < 0) {
		fprintf(stderr, "Failed to create RAW socket for Profinet TSN Low Frames!\n");
		return socket_fd;
	}

	/* Adjust filter: VLAN TCI */
	tsn_low_frame_filter[3].k = app_config.classes[TSN_LOW_FRAME_TYPE].vid |
				    app_config.classes[TSN_LOW_FRAME_TYPE].pcp << VLAN_PCP_SHIFT;

	ret = setsockopt(socket_fd, SOL_SOCKET, SO_ATTACH_FILTER, &tsn_low_filter_program,
			 sizeof(tsn_low_filter_program));
	if (ret < 0) {
		perror("setsockopt() failed");
		goto err_filter;
	}

	/* Mark socket as non-blocking */
	ret = mark_socket_non_blocking(socket_fd);
	if (ret) {
		fprintf(stderr, "Failed to mark TSN Low socket as non-blocking!\n");
		goto err_filter;
	}

	/* Enable SO_TXTIME */
	if (!app_config.classes[TSN_LOW_FRAME_TYPE].tx_time_enabled)
		goto out;

	sk_txtime.clockid = CLOCK_TAI; /* For hardware offload CLOCK_TAI is mandatory */
	sk_txtime.flags = 1 << 1;      /* Enable error reporting */
	ret = setsockopt(socket_fd, SOL_SOCKET, SO_TXTIME, &sk_txtime, sizeof(sk_txtime));
	if (ret) {
		perror("setsockopt() failed");
		goto err_filter;
	}

out:
	return socket_fd;

err_filter:
	close(socket_fd);
	return -errno;
}

int create_rtc_socket(void)
{
	const struct sock_fprog rtc_filter_program = {.len = ARRAY_SIZE(rtc_frame_filter),
						      .filter = rtc_frame_filter};
	int socket_fd, ret;

	socket_fd = create_raw_socket(app_config.classes[RTC_FRAME_TYPE].interface,
				      app_config.classes[RTC_FRAME_TYPE].socket_priority);
	if (socket_fd < 0) {
		fprintf(stderr, "Failed to create RAW socket for Profinet RTC Frames!\n");
		return socket_fd;
	}

	/* Adjust filter: VLAN TCI */
	rtc_frame_filter[3].k = app_config.classes[RTC_FRAME_TYPE].vid |
				app_config.classes[RTC_FRAME_TYPE].pcp << VLAN_PCP_SHIFT;

	ret = setsockopt(socket_fd, SOL_SOCKET, SO_ATTACH_FILTER, &rtc_filter_program,
			 sizeof(rtc_filter_program));
	if (ret < 0) {
		perror("setsockopt() failed");
		goto err_filter;
	}

	/* Mark socket as non-blocking */
	ret = mark_socket_non_blocking(socket_fd);
	if (ret) {
		fprintf(stderr, "Failed to mark Rtc socket as non-blocking!\n");
		goto err_filter;
	}

	return socket_fd;

err_filter:
	close(socket_fd);
	return -errno;
}

int create_rta_socket(void)
{
	const struct sock_fprog rta_filter_program = {.len = ARRAY_SIZE(rta_frame_filter),
						      .filter = rta_frame_filter};
	int socket_fd, ret;

	socket_fd = create_raw_socket(app_config.classes[RTA_FRAME_TYPE].interface,
				      app_config.classes[RTA_FRAME_TYPE].socket_priority);
	if (socket_fd < 0) {
		fprintf(stderr, "Failed to create RAW socket for Profinet RTA Frames!\n");
		return socket_fd;
	}

	/* Adjust filter: VLAN TCI */
	rta_frame_filter[3].k = app_config.classes[RTA_FRAME_TYPE].vid |
				app_config.classes[RTA_FRAME_TYPE].pcp << VLAN_PCP_SHIFT;

	ret = setsockopt(socket_fd, SOL_SOCKET, SO_ATTACH_FILTER, &rta_filter_program,
			 sizeof(rta_filter_program));
	if (ret < 0) {
		perror("setsockopt() failed");
		goto err_filter;
	}

	/* Mark socket as non-blocking */
	ret = mark_socket_non_blocking(socket_fd);
	if (ret) {
		fprintf(stderr, "Failed to mark TSN High socket as non-blocking!\n");
		goto err_filter;
	}

	return socket_fd;

err_filter:
	close(socket_fd);
	return -errno;
}

int create_dcp_socket(void)
{
	const struct sock_fprog dcp_filter_program = {.len = ARRAY_SIZE(dcp_frame_filter),
						      .filter = dcp_frame_filter};
	int socket_fd, ret;

	socket_fd = create_raw_socket(app_config.classes[DCP_FRAME_TYPE].interface,
				      app_config.classes[DCP_FRAME_TYPE].socket_priority);
	if (socket_fd < 0) {
		fprintf(stderr, "Failed to create RAW socket for Profinet DCP Frames!\n");
		return socket_fd;
	}

	/* Adjust filter: VLAN TCI */
	dcp_frame_filter[3].k = app_config.classes[DCP_FRAME_TYPE].vid |
				app_config.classes[DCP_FRAME_TYPE].pcp << VLAN_PCP_SHIFT;

	ret = setsockopt(socket_fd, SOL_SOCKET, SO_ATTACH_FILTER, &dcp_filter_program,
			 sizeof(dcp_filter_program));
	if (ret < 0) {
		perror("setsockopt() failed");
		goto err_filter;
	}

	/* Mark socket as non-blocking */
	ret = mark_socket_non_blocking(socket_fd);
	if (ret) {
		fprintf(stderr, "Failed to mark Dcp socket as non-blocking!\n");
		goto err_filter;
	}

	return socket_fd;

err_filter:
	close(socket_fd);
	return -errno;
}

int create_lldp_socket(void)
{
	const struct sock_fprog lldp_filter_program = {.len = ARRAY_SIZE(lldp_frame_filter),
						       .filter = lldp_frame_filter};
	int socket_fd, ret;

	socket_fd = create_raw_socket(app_config.classes[LLDP_FRAME_TYPE].interface,
				      app_config.classes[LLDP_FRAME_TYPE].socket_priority);
	if (socket_fd < 0) {
		fprintf(stderr, "Failed to create RAW socket for LLDP Frames!\n");
		return socket_fd;
	}

	ret = setsockopt(socket_fd, SOL_SOCKET, SO_ATTACH_FILTER, &lldp_filter_program,
			 sizeof(lldp_filter_program));
	if (ret < 0) {
		perror("setsockopt() failed");
		goto err_filter;
	}

	/* Mark socket as non-blocking */
	ret = mark_socket_non_blocking(socket_fd);
	if (ret) {
		fprintf(stderr, "Failed to mark Lldp socket as non-blocking!\n");
		goto err_filter;
	}

	return socket_fd;

err_filter:
	close(socket_fd);
	return -errno;
}

int create_generic_l2_socket(void)
{
	const struct sock_fprog generic_l2_filter_program = {
		.len = ARRAY_SIZE(generic_l2_frame_filter), .filter = generic_l2_frame_filter};
	struct sock_txtime sk_txtime;
	int socket_fd, ret;

	socket_fd = create_raw_socket(app_config.classes[GENERICL2_FRAME_TYPE].interface,
				      app_config.classes[GENERICL2_FRAME_TYPE].socket_priority);
	if (socket_fd < 0) {
		fprintf(stderr, "Failed to create RAW socket for Generic L2 Frames!\n");
		return socket_fd;
	}

	/* Adjust filter: EtherType and VLAN TCI */
	generic_l2_frame_filter[1].k = app_config.classes[GENERICL2_FRAME_TYPE].ether_type;
	generic_l2_frame_filter[3].k = app_config.classes[GENERICL2_FRAME_TYPE].vid |
				       app_config.classes[GENERICL2_FRAME_TYPE].pcp
					       << VLAN_PCP_SHIFT;

	ret = setsockopt(socket_fd, SOL_SOCKET, SO_ATTACH_FILTER, &generic_l2_filter_program,
			 sizeof(generic_l2_filter_program));
	if (ret < 0) {
		perror("setsockopt() failed");
		goto err_filter;
	}

	/* Mark socket as non-blocking */
	ret = mark_socket_non_blocking(socket_fd);
	if (ret) {
		fprintf(stderr, "Failed to mark Generic L2 socket as non-blocking!\n");
		goto err_filter;
	}

	/* Enable SO_TXTIME */
	if (!app_config.classes[GENERICL2_FRAME_TYPE].tx_time_enabled)
		goto out;

	sk_txtime.clockid = CLOCK_TAI; /* For hardware offload CLOCK_TAI is mandatory */
	sk_txtime.flags = 1 << 1;      /* Enable error reporting */
	ret = setsockopt(socket_fd, SOL_SOCKET, SO_TXTIME, &sk_txtime, sizeof(sk_txtime));
	if (ret) {
		perror("setsockopt() failed");
		goto err_filter;
	}

out:
	return socket_fd;

err_filter:
	close(socket_fd);
	return -errno;
}

static int dns_lookup(const char *host, const char *port, struct sockaddr_storage *addr,
		      int *socket_fd)
{
	struct addrinfo *sa_head, *sa, hints;
	int ret, sock;

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_family = PF_UNSPEC;
	hints.ai_flags = AI_ADDRCONFIG;

	ret = getaddrinfo(host, port, &hints, &sa_head);
	if (ret) {
		fprintf(stderr, "getaddrinfo() for host '%s' failed: %s!\n", host,
			gai_strerror(ret));
		ret = -EINVAL;
		goto err_addrinfo;
	}

	for (sa = sa_head; sa != NULL; sa = sa->ai_next) {
		sock = socket(sa->ai_family, sa->ai_socktype, sa->ai_protocol);
		if (sock < 0) {
			perror("socket() failed");
			continue;
		}

		if (socket_fd)
			*socket_fd = sock;
		else
			close(sock);

		if (addr)
			memcpy(addr, sa->ai_addr, sa->ai_addrlen);
		break;
	}

	if (!sa) {
		fprintf(stderr, "No DNS record for host %s at %s found!\n", host, port);
		ret = -EINVAL;
		goto err_dns;
	}

	ret = 0;

err_dns:
	freeaddrinfo(sa_head);
err_addrinfo:
	return ret;
}

int create_udp_socket(const char *udp_destination, const char *udp_source, const char *udp_port,
		      int socket_priority, struct sockaddr_storage *destination)
{
	struct sockaddr_storage source;
	int ret, socket_fd = -1;

	ret = dns_lookup(udp_destination, udp_port, destination, NULL);
	if (ret)
		goto err_dns1;

	ret = dns_lookup(udp_source, udp_port, &source, &socket_fd);
	if (ret)
		goto err_dns2;

	switch (source.ss_family) {
	case AF_INET:
		ret = bind(socket_fd, (struct sockaddr_in *)&source, sizeof(struct sockaddr_in));
		break;
	case AF_INET6:
		ret = bind(socket_fd, (struct sockaddr_in6 *)&source, sizeof(struct sockaddr_in6));
		break;
	default:
		ret = -EINVAL;
	}

	if (ret) {
		perror("bind() failed");
		goto err_bind;
	}

	ret = setsockopt(socket_fd, SOL_SOCKET, SO_PRIORITY, &socket_priority,
			 sizeof(socket_priority));
	if (ret) {
		perror("setsockopt() failed");
		goto err_prio;
	}

	/* Mark socket as non-blocking */
	ret = mark_socket_non_blocking(socket_fd);
	if (ret) {
		fprintf(stderr, "Failed to mark UDP socket as non-blocking!\n");
		goto err_nonblocking;
	}

	return socket_fd;

err_nonblocking:
err_prio:
err_bind:
	close(socket_fd);
err_dns2:
err_dns1:
	return ret;
}

int create_udp_cl_socket(const char *udp_destination, const char *udp_port,
			 struct sockaddr_storage *destination)
{
	int ret, socket = -1;

	ret = dns_lookup(udp_destination, udp_port, destination, &socket);
	if (ret)
		goto err;

	return socket;

err:
	return ret;
}
