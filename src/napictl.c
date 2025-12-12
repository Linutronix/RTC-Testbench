// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2025 Linutronix GmbH
 *
 * Configure NAPI defer-hard-irqs and/or gro-flush-timeout via netlink genl API.
 *
 * Note: Requires recent kernel and driver support. Works for igc and igb.
 */
#include <errno.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/netdev.h>
#include <net/if.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/netlink.h>

#include "app_config.h"

static struct option long_options[] = {
	{"interface", optional_argument, NULL, 'i'},
	{"queue", optional_argument, NULL, 'q'},
	{"defer-hard-irqs", optional_argument, NULL, 'd'},
	{"gro-flush-timeout", optional_argument, NULL, 'g'},
	{"help", no_argument, NULL, 'h'},
	{"verbose", no_argument, NULL, 'v'},
	{"version", no_argument, NULL, 'V'},
	{NULL},
};

static const char *interface;
static int queue;
static int verbose;
static unsigned int defer_hard_irqs;
static unsigned int gro_flush_timeout;

static void print_usage_and_die(void)
{
	fprintf(stderr, "usage: napictl [options]\n");
	fprintf(stderr, "  options:\n");
	fprintf(stderr, "    -i, --interface:         Network interface to configure\n");
	fprintf(stderr, "    -q, --queue:             Queue of network interface to configure\n");
	fprintf(stderr, "    -d, --defer-hard-irqs:   Set defer-hard-irqs\n");
	fprintf(stderr, "    -g, --gro-flush-timeout: Set gro-flush-timeout\n");
	fprintf(stderr, "    -h, --help:              Print this help text\n");
	fprintf(stderr, "    -v, --verbose:           Print verbose messages\n");
	fprintf(stderr, "    -V, --version:           Print version\n");

	exit(EXIT_SUCCESS);
}

static void print_version_and_die(void)
{
	printf("napictl: version \"%s\"\n", VERSION);
	exit(EXIT_SUCCESS);
}

static void vprint(const char *format, ...)
{
	va_list args;

	if (!verbose)
		return;

	va_start(args, format);
	vprintf(format, args);
	va_end(args);
}

/* NAPI ID(s) for queue */
static unsigned int napi_id_tx;
static unsigned int napi_id_rx;

static int parse_queue(struct nl_msg *msg, void *arg)
{
	bool q_found = false, n_found = false, t_found = false;
	struct nlattr *attrs[NETDEV_A_QUEUE_MAX + 1];
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	unsigned int q, n, t;

	genlmsg_parse(nlh, 0, attrs, NETDEV_A_QUEUE_MAX, NULL);

	if (attrs[NETDEV_A_QUEUE_ID]) {
		q = nla_get_u32(attrs[NETDEV_A_QUEUE_ID]);
		q_found = true;
		vprint(">> Queue ID: %u\n", q);
	}
	if (attrs[NETDEV_A_QUEUE_NAPI_ID]) {
		n = nla_get_u32(attrs[NETDEV_A_QUEUE_NAPI_ID]);
		n_found = true;
		vprint(">> Queue NAPI ID: %u\n", n);
	}

	if (attrs[NETDEV_A_QUEUE_TYPE]) {
		t = nla_get_u32(attrs[NETDEV_A_QUEUE_TYPE]);
		t_found = true;
		vprint(">> Queue Type: %u\n", t);
	}

	if (q_found && n_found && t_found && q == queue) {
		if (t == NETDEV_QUEUE_TYPE_RX)
			napi_id_rx = n;
		if (t == NETDEV_QUEUE_TYPE_TX)
			napi_id_tx = n;
	}

	return NL_OK;
}

static int get_napi_id(int ifindex)
{
	struct nl_sock *sock;
	struct nl_msg *msg;
	int family, ret;

	sock = nl_socket_alloc();
	if (!sock) {
		fprintf(stderr, "nl_socket_alloc() failed: %m\n");
		return -errno;
	}

	ret = genl_connect(sock);
	if (ret) {
		fprintf(stderr, "genl_connect() failed: %m\n");
		goto out;
	}

	family = genl_ctrl_resolve(sock, NETDEV_FAMILY_NAME);
	if (family < 0) {
		fprintf(stderr, "genl_ctrl_resolve() failed: %s\n", nl_geterror(family));
		ret = family;
		goto out;
	}

	msg = nlmsg_alloc();
	if (!msg) {
		fprintf(stderr, "nlmsg_alloc() failed: %m\n");
		ret = -errno;
		goto out;
	}

	/* NETDEV_CMD_QUEUE_GET */
	genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family, 0, NLM_F_DUMP, NETDEV_CMD_QUEUE_GET, 0);
	nla_put_u32(msg, NETDEV_A_QUEUE_IFINDEX, ifindex);
	nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, parse_queue, NULL);

	ret = nl_send_auto(sock, msg);
	if (ret < 0) {
		fprintf(stderr, "nl_send_auto() failed: %s\n", nl_geterror(ret));
		nlmsg_free(msg);
		goto out;
	}
	nlmsg_free(msg);

	vprint("> Query queues and NAPI ids\n");
	ret = nl_recvmsgs_default(sock);
	if (ret < 0)
		fprintf(stderr, "nl_recvmsgs_default() failed: %s\n", nl_geterror(ret));

out:
	nl_socket_free(sock);
	return ret;
}

static int set_napi_attributes(int ifindex, unsigned int napi_id)
{
	struct nl_sock *sock;
	struct nl_msg *msg;
	int family, ret;

	sock = nl_socket_alloc();
	if (!sock) {
		fprintf(stderr, "nl_socket_alloc() failed: %m\n");
		return -errno;
	}

	ret = genl_connect(sock);
	if (ret) {
		fprintf(stderr, "genl_connect() failed: %m\n");
		goto out;
	}

	family = genl_ctrl_resolve(sock, NETDEV_FAMILY_NAME);
	if (family < 0) {
		fprintf(stderr, "genl_ctrl_resolve() failed: %s\n", nl_geterror(family));
		ret = family;
		goto out;
	}

	msg = nlmsg_alloc();
	if (!msg) {
		fprintf(stderr, "nlmsg_alloc() failed: %m\n");
		ret = -errno;
		goto out;
	}

	/* NETDEV_CMD_NAPI_SET */
	genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, family, 0, NLM_F_REQUEST | NLM_F_ACK,
		    NETDEV_CMD_NAPI_SET, 0);

	nla_put_u32(msg, NETDEV_A_NAPI_ID, napi_id);
	nla_put_u32(msg, NETDEV_A_NAPI_DEFER_HARD_IRQS, defer_hard_irqs);
	nla_put_u32(msg, NETDEV_A_NAPI_GRO_FLUSH_TIMEOUT, gro_flush_timeout);

	ret = nl_send_auto(sock, msg);
	if (ret < 0) {
		fprintf(stderr, "nl_send_auto() failed: %s\n", nl_geterror(ret));
		nlmsg_free(msg);
		goto out;
	}
	nlmsg_free(msg);

	vprint("> Query queues and NAPI ids\n");
	ret = nl_recvmsgs_default(sock);
	if (ret < 0)
		fprintf(stderr, "nl_recvmsgs_default() failed: %s\n", nl_geterror(ret));

out:
	nl_socket_free(sock);
	return ret;
}

int main(int argc, char **argv)
{
	int c, ret, ifindex;

	while ((c = getopt_long(argc, argv, "i:q:d:g:hvV", long_options, NULL)) != -1) {
		switch (c) {
		case 'V':
			print_version_and_die();
			break;
		case 'v':
			verbose = 1;
			break;
		case 'i':
			interface = optarg;
			break;
		case 'q':
			queue = atoi(optarg);
			break;
		case 'd':
			defer_hard_irqs = atoi(optarg);
			break;
		case 'g':
			gro_flush_timeout = atoi(optarg);
			break;
		case 'h':
		default:
			print_usage_and_die();
		}
	}

	if (!interface || queue < 0 || defer_hard_irqs < 0 || gro_flush_timeout < 0)
		print_usage_and_die();

	ifindex = if_nametoindex(interface);
	if (!ifindex) {
		fprintf(stderr, "if_nametoindex() failed\n");
		return EXIT_FAILURE;
	}

	ret = get_napi_id(ifindex);
	if (ret) {
		fprintf(stderr, "get_napi_id() failed\n");
		return EXIT_FAILURE;
	}

	vprint("> Tx NAPI ID for queue %d: %u\n", queue, napi_id_tx);
	vprint("> Rx NAPI ID for queue %d: %u\n", queue, napi_id_rx);

	vprint("> Set defer-hard-irqs %u and gro-flush-time %u to NAPI ID %u\n", defer_hard_irqs,
	       gro_flush_timeout, napi_id_rx);

	ret = set_napi_attributes(ifindex, napi_id_rx);
	if (ret) {
		fprintf(stderr, "set_napi_attributes() failed\n");
		return EXIT_FAILURE;
	}

	vprint("> Set defer-hard-irqs %u and gro-flush-time %u to NAPI ID %u\n", defer_hard_irqs,
	       gro_flush_timeout, napi_id_tx);

	ret = set_napi_attributes(ifindex, napi_id_tx);
	if (ret) {
		fprintf(stderr, "set_napi_attributes() failed\n");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
