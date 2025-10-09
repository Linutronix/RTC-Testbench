// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2021-2025 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include <net/if.h>
#include <netdb.h>

#include <arpa/inet.h>

#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/ip.h>
#include <linux/limits.h>
#include <linux/net_tstamp.h>
#include <linux/sockios.h>
#include <linux/udp.h>
#include <stdio.h>
#include <sys/ioctl.h>

#include "app_config.h"

#include "config.h"
#include "log.h"
#include "net.h"
#include "security.h"
#include "stat.h"
#include "tx_time.h"
#include "utils.h"
#include "xdp.h"
#include "xdp_metadata.h"

static int program_loaded;
static int xsks_map;

static enum xdp_attach_mode xdp_flags(bool skb_mode)
{
	return skb_mode ? XDP_MODE_SKB : XDP_MODE_NATIVE;
}

static void xdp_set_prog_bind_flags(struct bpf_object *obj, unsigned int if_index)
{
#ifdef RX_TIMESTAMP
	struct bpf_program *bpf_prog = bpf_object__find_program_by_name(obj, "xdp_sock_prog");

	bpf_program__set_ifindex(bpf_prog, if_index);
	bpf_program__set_flags(bpf_prog, BPF_F_XDP_DEV_BOUND_ONLY);
	setenv("LIBXDP_SKIP_DISPATCHER", "1", 1);
#endif
}

#ifdef TX_TIMESTAMP
static int xdp_enable_hw_tx_timestamping(const char *if_name)
{
	struct ifreq ifr = {};
	struct hwtstamp_config hwconfig = {};
	int socket_fd;

	socket_fd = socket(PF_INET, SOCK_DGRAM, 0);
	if (socket_fd < 0) {
		fprintf(stderr, "XdpTxHwTs: Failed to create socket for interface %s: %s\n",
			if_name, strerror(errno));
		return -errno;
	}

	strncpy(ifr.ifr_name, if_name, IFNAMSIZ - 1);
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';
	ifr.ifr_data = (char *)&hwconfig;

	if (ioctl(socket_fd, SIOCGHWTSTAMP, &ifr) < 0) {
		fprintf(stderr, "XdpTxHwTs: Failed to read HW timestamp config for %s: %s\n",
			if_name, strerror(errno));
		close(socket_fd);
		return -errno;
	}

	if (hwconfig.rx_filter != HWTSTAMP_FILTER_NONE) {
		log_message(
			LOG_LEVEL_INFO,
			"XdpTxHwTs: ptp4l or another service already configured RX HW timestamping "
			"on %s — keeping existing RX settings\n",
			if_name);
	}

	if (hwconfig.tx_type == HWTSTAMP_TX_ON) {
		log_message(
			LOG_LEVEL_INFO,
			"XdpTxHwTs: TX HW timestamping already enabled on %s — skipping reapply\n",
			if_name);
		close(socket_fd);
		return 0;
	}

	/* Only change TX type, keep RX settings */
	hwconfig.tx_type = HWTSTAMP_TX_ON;
	ifr.ifr_data = (char *)&hwconfig;

	if (ioctl(socket_fd, SIOCSHWTSTAMP, &ifr) < 0) {
		if (errno == EINVAL || errno == EOPNOTSUPP) {
			fprintf(stderr,
				"XdpTxHwTs: HW timestamping not supported by driver on %s\n",
				if_name);
		} else {
			fprintf(stderr,
				"XdpTxHwTs: Failed to enable HW TX timestamping on %s: %s\n",
				if_name, strerror(errno));
		}
		close(socket_fd);
		return -errno;
	}

	log_message(
		LOG_LEVEL_INFO,
		"XdpTxHwTs: HW TX timestamping enabled for interface %s (RX config preserved)\n",
		if_name);
	close(socket_fd);
	return 0;
}

static void xdp_process_tx_timestamp(struct xdp_socket *xsk, uint32_t idx_cq)
{
	struct round_trip_context *rtt = xsk->rtt;
	uint64_t seq = xsk->tx_hw_ts_seq_lagged;
	size_t idx = seq % rtt->backlog_len;

	uint64_t addr = *xsk_ring_cons__comp_addr(&xsk->umem.cq, idx_cq);
	unsigned char *data = xsk_umem__get_data(xsk->umem.buffer, addr);
	struct xsk_tx_metadata *meta =
		(struct xsk_tx_metadata *)(data - sizeof(struct xsk_tx_metadata));

	log_message(LOG_LEVEL_DEBUG,
		    "XdpTxHwTs CQ[0]: addr=0x%llx, flags=0x%llx, ts=%llu, seq=%llu, idx=%zu\n",
		    (unsigned long long)addr, (unsigned long long)meta->flags,
		    (unsigned long long)meta->completion.tx_timestamp, (unsigned long long)seq,
		    idx);

	if (meta->flags & XDP_TXMD_FLAGS_TIMESTAMP) {
		rtt->backlog[idx].hw_ts = meta->completion.tx_timestamp;

		/* Determine the frame type from the round trip context */
		enum stat_frame_type frame_type = (enum stat_frame_type)(rtt - round_trip_contexts);
		stat_frame_sent_latency(frame_type, seq);

		/*
		 * Calculate device latency (RX HW to TX HW) only for mirror mode and valid HW
		 * timestamp
		 */
		if (log_stat_user_selected == LOG_TX_TIMESTAMPS && config_have_rx_timestamp() &&
		    meta->completion.tx_timestamp > rtt->backlog[idx].sw_ts) {
			stat_frame_device_latency(frame_type, seq, meta->completion.tx_timestamp);
		}
	} else {
		log_message(LOG_LEVEL_WARNING,
			    "XDP TX HW timestamp missing for expected seq %" PRIu64 ", idx=%zu\n",
			    seq, idx);
	}
}
#endif

static int xdp_load_program(struct xdp_socket *xsk, const char *interface, const char *xdp_program,
			    int skb_mode)
{
	struct xdp_program *prog;
	struct bpf_object *obj;
	unsigned int if_index;
	struct bpf_map *map;
	int ret;

	if (!xdp_program) {
		fprintf(stderr, "No XDP program specified!\n");
		fprintf(stderr, "Have a look at the example configurations.\n");
		return -EINVAL;
	}

	/*
	 * The eBPF program for this application instance needs to be attached to the network
	 * interface only once.
	 *
	 * When multiple instances are executed in parallel, xdp_program__attach() will try to
	 * automatically attach the new eBPF program to the existing ones by utilizing the libxdp
	 * dispatcher master program. Therefore, all applications have to use libxdp and specify
	 * their metadata e.g., priority accordingly.
	 */
	if (program_loaded)
		return 0;

	if_index = if_nametoindex(interface);
	if (!if_index) {
		fprintf(stderr, "if_nametoindex() failed\n");
		return -EINVAL;
	}

	prog = xdp_program__open_file(xdp_program, "xdp_sock", NULL);
	ret = libxdp_get_error(prog);
	if (ret) {
		char tmp[PATH_MAX];

		/* Try to load the XDP program from data directory instead */
		snprintf(tmp, sizeof(tmp), "%s/%s", INSTALL_EBPF_DIR, xdp_program);
		prog = xdp_program__open_file(tmp, "xdp_sock", NULL);
		ret = libxdp_get_error(prog);
		if (ret) {
			fprintf(stderr, "xdp_program__open_file() failed\n");
			return -EINVAL;
		}
	}

	obj = xdp_program__bpf_obj(prog);
	if (config_have_rx_timestamp())
		xdp_set_prog_bind_flags(obj, if_index);

	ret = xdp_program__attach(prog, if_index, xdp_flags(skb_mode), 0);
	if (ret) {
		fprintf(stderr, "xdp_program__attach() failed\n");
		return -EINVAL;
	}

	/* Locate xsks_map for AF_XDP socket code */
	map = bpf_object__find_map_by_name(obj, "xsks_map");
	xsks_map = bpf_map__fd(map);
	if (xsks_map < 0) {
		fprintf(stderr, "No xsks_map found!\n");
		return -EINVAL;
	}

	program_loaded = 1;
	xsk->prog = prog;

	return 0;
}

static int xdp_configure_socket_options(struct xdp_socket *xsk, bool busy_poll_mode)
{
	int ret = -EINVAL;

	if (!busy_poll_mode)
		return 0;

#if defined(HAVE_SO_BUSY_POLL) && defined(HAVE_SO_PREFER_BUSY_POLL) &&                             \
	defined(HAVE_SO_BUSY_POLL_BUDGET)
	int opt;

	/* busy poll enable */
	opt = 1;
	ret = setsockopt(xsk_socket__fd(xsk->xsk), SOL_SOCKET, SO_PREFER_BUSY_POLL, (void *)&opt,
			 sizeof(opt));
	if (ret) {
		perror("setsockopt() failed");
		return ret;
	}

	/* poll for 20us if socket not ready */
	opt = 20;
	ret = setsockopt(xsk_socket__fd(xsk->xsk), SOL_SOCKET, SO_BUSY_POLL, (void *)&opt,
			 sizeof(opt));
	if (ret) {
		perror("setsockopt() failed");
		return ret;
	}

	/* send/recv XDP_BATCH_SIZE packets at most */
	opt = XDP_BATCH_SIZE;
	ret = setsockopt(xsk_socket__fd(xsk->xsk), SOL_SOCKET, SO_BUSY_POLL_BUDGET, (void *)&opt,
			 sizeof(opt));
	if (ret) {
		perror("setsockopt() failed");
		return ret;
	}

	xsk->busy_poll_mode = true;
#endif

	return ret;
}

static int xdp_umem_create(struct xdp_socket *xsk, bool tx_time_mode, bool tx_hwtstamp_mode)
{
	void *buffer = NULL;
	int ret;

	/* Allocate user space memory for xdp frames */
	ret = posix_memalign(&buffer, sysconf(_SC_PAGE_SIZE), XDP_NUM_FRAMES * XDP_FRAME_SIZE);
	if (ret) {
		fprintf(stderr, "posix_memalign() failed\n");
		return -ENOMEM;
	}
	memset(buffer, '\0', XDP_NUM_FRAMES * XDP_FRAME_SIZE);

	/*
	 * libxdp >= 1.5.0 supports Tx metadata via xsk_umem__create_opts().
	 * Enable metadata if either tx_time_mode or tx_hwtstamp_mode is true.
	 */
#if defined(HAVE_XDP_TX_TIME) || defined(TX_TIMESTAMP)
	bool use_tx_metadata = tx_time_mode || tx_hwtstamp_mode;

	DECLARE_LIBXDP_OPTS(
		xsk_umem_opts, cfg, .size = XDP_NUM_FRAMES * XDP_FRAME_SIZE,
		.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
		.comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS, .frame_size = XDP_FRAME_SIZE,
		.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
		/* struct xsk_tx_metadata contains all AF_XDP offload requests. */
		.flags = use_tx_metadata ? XDP_UMEM_TX_METADATA_LEN : 0,
		.tx_metadata_len = use_tx_metadata ? sizeof(struct xsk_tx_metadata) : 0, );

	xsk->umem.umem = xsk_umem__create_opts(buffer, &xsk->umem.fq, &xsk->umem.cq, &cfg);
	if (!xsk->umem.umem) {
		ret = -errno;
		fprintf(stderr, "xsk_umem__create_opts() failed: %s\n", strerror(-ret));
		goto err;
	}
#else
	struct xsk_umem_config cfg = {
		.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
		.comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.frame_size = XDP_FRAME_SIZE,
		.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
		.flags = 0,
	};

	ret = xsk_umem__create(&xsk->umem.umem, buffer, XDP_NUM_FRAMES * XDP_FRAME_SIZE,
			       &xsk->umem.fq, &xsk->umem.cq, &cfg);
	if (ret) {
		fprintf(stderr, "xsk_umem__create() failed: %s\n", strerror(-ret));
		goto err;
	}
#endif

	xsk->umem.buffer = buffer;
	xsk->tx_time_mode = tx_time_mode;
	xsk->tx_hwtstamp_mode = tx_hwtstamp_mode;
	return 0;

err:
	free(buffer);
	return ret;
}

struct xdp_socket *xdp_open_socket(const char *interface, const char *xdp_program, int queue,
				   bool skb_mode, bool zero_copy_mode, bool wakeup_mode,
				   bool busy_poll_mode, bool tx_time_mode, bool tx_hwtstamp_mode)
{
	struct xsk_socket_config xsk_cfg;
	struct xdp_socket *xsk;
	int ret, i, fd;
	uint32_t idx;

	xsk = calloc(1, sizeof(*xsk));
	if (!xsk)
		return NULL;

	ret = xdp_load_program(xsk, interface, xdp_program, skb_mode);
	if (ret)
		goto err;

#ifdef TX_TIMESTAMP
	/* Enable HW TX timestamping if requested */
	if (tx_hwtstamp_mode) {
		ret = xdp_enable_hw_tx_timestamping(interface);
		if (ret) {
			fprintf(stderr, "Failed to enable HW TX timestamping on %s!\n", interface);
			goto err;
		}
	}
#endif

	/* Allocate and register AF_XDP umem area */
	ret = xdp_umem_create(xsk, tx_time_mode, tx_hwtstamp_mode);
	if (ret) {
		fprintf(stderr, "Failed to allocate AF_XDP UMEM area!\n");
		goto err2;
	}

	/* Add some buffers */
	ret = xsk_ring_prod__reserve(&xsk->umem.fq, XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);
	if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS) {
		fprintf(stderr, "xsk_ring_prod__reserve() failed\n");
		goto err3;
	}

	for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++) {
		*xsk_ring_prod__fill_addr(&xsk->umem.fq, idx) = i * XDP_FRAME_SIZE;

		/* Reserve space for Tx Meta Data on retransmit. */
#if defined(HAVE_XDP_TX_TIME) || defined(TX_TIMESTAMP)
		if (tx_time_mode || tx_hwtstamp_mode)
			*xsk_ring_prod__fill_addr(&xsk->umem.fq, idx) +=
				sizeof(struct xsk_tx_metadata);
#endif
		idx++;
	}

	xsk_ring_prod__submit(&xsk->umem.fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);

	/* Create XDP socket */
	xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
	xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
	xsk_cfg.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
	xsk_cfg.xdp_flags = skb_mode ? XDP_FLAGS_SKB_MODE : XDP_FLAGS_DRV_MODE;
	xsk_cfg.bind_flags = wakeup_mode ? XDP_USE_NEED_WAKEUP : 0;
	xsk_cfg.bind_flags |= zero_copy_mode ? XDP_ZEROCOPY : XDP_COPY;

	ret = xsk_socket__create(&xsk->xsk, interface, queue, xsk->umem.umem, &xsk->rx, &xsk->tx,
				 &xsk_cfg);
	if (ret) {
		fprintf(stderr, "xsk_socket__create() failed: %s\n", strerror(-ret));
		goto err3;
	}

	/* Add xsk into xsks_map */
	fd = xsk_socket__fd(xsk->xsk);
	ret = bpf_map_update_elem(xsks_map, &queue, &fd, 0);
	if (ret) {
		fprintf(stderr, "bpf_map_update_elem() failed: %s\n", strerror(-ret));
		goto err4;
	}

	/* Set socket options */
	ret = xdp_configure_socket_options(xsk, busy_poll_mode);
	if (ret) {
		fprintf(stderr, "Failed to configure busy polling!\n");
		goto err4;
	}

	return xsk;

err4:
	xsk_socket__delete(xsk->xsk);
err3:
	free(xsk->umem.buffer);
	xsk_umem__delete(xsk->umem.umem);
err2:
err:
	free(xsk);
	return NULL;
}

void xdp_close_socket(struct xdp_socket *xsk, const char *interface, bool skb_mode)
{
	unsigned int if_index;

	if (!xsk)
		return;

	xsk_socket__delete(xsk->xsk);
	xsk_umem__delete(xsk->umem.umem);

	if_index = if_nametoindex(interface);
	if (!if_index) {
		fprintf(stderr, "if_nametoindex() failed\n");
		return;
	}

	if (xsk->prog) {
		xdp_program__detach(xsk->prog, if_index, xdp_flags(skb_mode), 0);
		xdp_program__close(xsk->prog);
		program_loaded = 0;
	}

	free(xsk->umem.buffer);
	free(xsk);
}

void xdp_complete_tx_only(struct xdp_socket *xsk)
{
	size_t ndescs = xsk->outstanding_tx;
	unsigned int received;
	uint32_t idx_cq = 0;

	if (!xsk->outstanding_tx)
		return;

	/* Kick kernel to Tx packets */
	if (xsk->busy_poll_mode || xsk_ring_prod__needs_wakeup(&xsk->tx))
		sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

	/* Buffers transmitted? */
	received = xsk_ring_cons__peek(&xsk->umem.cq, ndescs, &idx_cq);
	if (!received)
		return;

#ifdef TX_TIMESTAMP
	if (xsk->tx_hwtstamp_mode) {
		xdp_process_tx_timestamp(xsk, idx_cq);
	}
#endif

	xsk_ring_cons__release(&xsk->umem.cq, received);
	xsk->outstanding_tx -= received;
}

void xdp_complete_tx(struct xdp_socket *xsk)
{
	size_t ndescs = xsk->outstanding_tx;
	uint32_t idx_cq = 0, idx_fq = 0;
	unsigned int received;
	int ret, i;

	if (!xsk->outstanding_tx)
		return;

	/* Kick kernel to Tx packets */
	if (xsk->busy_poll_mode || xsk_ring_prod__needs_wakeup(&xsk->tx))
		sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

	/* Buffers transmitted? */
	received = xsk_ring_cons__peek(&xsk->umem.cq, ndescs, &idx_cq);
	if (!received)
		return;

#ifdef TX_TIMESTAMP
	if (xsk->tx_hwtstamp_mode) {
		xdp_process_tx_timestamp(xsk, idx_cq);
	}
#endif

	/* Re-add for Rx */
	ret = xsk_ring_prod__reserve(&xsk->umem.fq, received, &idx_fq);
	while (ret != received) {
		if (ret < 0)
			log_message(LOG_LEVEL_ERROR, "XdpTx: xsk_ring_prod__reserve() failed\n");

		if (xsk->busy_poll_mode || xsk_ring_prod__needs_wakeup(&xsk->umem.fq))
			recvfrom(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL);
		ret = xsk_ring_prod__reserve(&xsk->umem.fq, received, &idx_fq);
	}

	/*
	 * Use explicit indexing to avoid re-reading comp[0], which was already accessed for HW
	 * timestamping
	 */
	for (i = 0; i < received; ++i) {
		uint64_t addr = *xsk_ring_cons__comp_addr(&xsk->umem.cq, idx_cq + i);
		*xsk_ring_prod__fill_addr(&xsk->umem.fq, idx_fq + i) = addr;
	}

	xsk_ring_prod__submit(&xsk->umem.fq, received);
	xsk_ring_cons__release(&xsk->umem.cq, received);
	xsk->outstanding_tx -= received;
}

static unsigned char *xdp_prepare_tx_desc(struct xdp_socket *xsk, struct xdp_desc *tx_desc,
					  const struct xdp_tx_time *tx_time, int i, bool tx)
{
	unsigned char *data;

#if defined(HAVE_XDP_TX_TIME) || defined(TX_TIMESTAMP)
	/* Add Tx Time or Tx HW Timestamp request if supported */
	if (xsk->tx_time_mode || xsk->tx_hwtstamp_mode) {
		struct xsk_tx_metadata *meta;

		/* Reserve meta data space for Tx Time and Tx HW Timestamp */
		if (tx)
			tx_desc->addr += sizeof(struct xsk_tx_metadata);

		data = xsk_umem__get_data(xsk->umem.buffer, tx_desc->addr);
		meta = (struct xsk_tx_metadata *)(data - sizeof(struct xsk_tx_metadata));

		/* Zero out entire metadata struct before filling */
		memset(meta, 0, sizeof(*meta));

		/* Set flags and request fields */
		meta->flags = 0;
#ifdef HAVE_XDP_TX_TIME
		if (xsk->tx_time_mode) {
			uint64_t time;

			meta->flags |= XDP_TXMD_FLAGS_LAUNCH_TIME;
			time = tx_time_get_frame_tx_time(
				tx_time->sequence_counter_begin + i, tx_time->duration,
				tx_time->num_frames_per_cycle, tx_time->tx_time_offset,
				tx_time->traffic_class);
			meta->request.launch_time = time;
		}
#endif
#ifdef TX_TIMESTAMP
		/* Only timestamp first packet per cycle */
		if (xsk->tx_hwtstamp_mode && i == 0) {
			meta->flags |= XDP_TXMD_FLAGS_TIMESTAMP;
			/* Initialize TX HW timestamp */
			meta->completion.tx_timestamp = 0;
		}
#endif
		tx_desc->options |= XDP_TX_METADATA;
	} else {
		data = xsk_umem__get_data(xsk->umem.buffer, tx_desc->addr);
	}
#else
	data = xsk_umem__get_data(xsk->umem.buffer, tx_desc->addr);
#endif

	return data;
}

void xdp_gen_and_send_frames(struct xdp_socket *xsk, const struct xdp_gen_config *xdp)
{
	struct timespec tx_time = {};
	uint32_t idx = 0;
	size_t i;

	if (xdp->num_frames_per_cycle == 0)
		return;

	if (xsk_ring_prod__reserve(&xsk->tx, xdp->num_frames_per_cycle, &idx) <
	    xdp->num_frames_per_cycle) {
		/*
		 * This should never happen. It means there're no more Tx descriptors available to
		 * transmit the frames from this very period. The only thing we can do here, is to
		 * come back later and hope the hardware did transmit some frames.
		 */
		log_message(LOG_LEVEL_ERROR, "XdpTx: Cannot allocate Tx descriptors!\n");
		xdp_complete_tx_only(xsk);
		return;
	}

	clock_gettime(app_config.application_clock_id, &tx_time);

	for (i = 0; i < xdp->num_frames_per_cycle; ++i) {
		struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&xsk->tx, idx + i);
		struct prepare_frame_config frame_config;
		struct vlan_ethernet_header *eth;
		unsigned char *data;
		int ret;

		tx_desc->addr = *xdp->frame_number * XDP_FRAME_SIZE;
		tx_desc->len = xdp->frame_length;

		*xdp->frame_number += 1;
		*xdp->frame_number = (*xdp->frame_number % XSK_RING_CONS__DEFAULT_NUM_DESCS) +
				     XSK_RING_PROD__DEFAULT_NUM_DESCS;

		/* Get frame and prepare it */
		data = xdp_prepare_tx_desc(xsk, tx_desc, xdp->tx_time, i, true);

		frame_config.mode = xdp->mode;
		frame_config.security_context = xdp->security_context;
		frame_config.iv_prefix = xdp->iv_prefix;
		frame_config.payload_pattern = xdp->payload_pattern;
		frame_config.payload_pattern_length = xdp->payload_pattern_length;
		frame_config.frame_data = data;
		frame_config.frame_length = xdp->frame_length;
		frame_config.num_frames_per_cycle = xdp->num_frames_per_cycle;
		frame_config.sequence_counter = xdp->sequence_counter_begin + i;
		frame_config.tx_timestamp = ts_to_ns(&tx_time);
		frame_config.meta_data_offset = xdp->meta_data_offset;

		ret = prepare_frame_for_tx(&frame_config);
		if (ret)
			log_message(LOG_LEVEL_ERROR, "XdpTx: Failed to prepare frame for Tx!\n");

		/*
		 * In debug monitor mode the first frame of each burst should have a different
		 * DA. This way, the oscilloscope can trigger for it.
		 */
		if (app_config.debug_monitor_mode && i == 0) {
			eth = (struct vlan_ethernet_header *)data;
			memcpy(eth->destination, app_config.debug_monitor_destination, ETH_ALEN);
		}
	}

	xsk_ring_prod__submit(&xsk->tx, xdp->num_frames_per_cycle);
	xsk->outstanding_tx += xdp->num_frames_per_cycle;

	/* Kick Tx */
	xdp_complete_tx_only(xsk);

	/* Log SW timestamps */
#ifdef TX_TIMESTAMP
	if (xsk->tx_hwtstamp_mode) {
		/*
		 * When TX HW timestamping is enabled, record SW timestamp once per cycle
		 * (for the first frame in this cycle) and count all frames
		 */
		stat_frames_sent_batch(xdp->frame_type, xdp->sequence_counter_begin,
				       xdp->num_frames_per_cycle);

		/* Update the sequence number for expected HW timestamp in next cycle */
		xsk->tx_hw_ts_seq_lagged = xdp->sequence_counter_begin;
		return;
	}
#endif
	/* Normal mode: record SW timestamp for each frame */
	for (i = 0; i < xdp->num_frames_per_cycle; ++i)
		stat_frame_sent(xdp->frame_type, xdp->sequence_counter_begin + i);
}

void xdp_get_timestamp_metadata(void *data, uint64_t *rx_hw_ts, uint64_t *rx_sw_ts)
{
	struct xdp_meta *meta;

	meta = data - sizeof(*meta);

	if (meta->hint_valid & XDP_META_FIELD_TS) {
		*rx_hw_ts = meta->rx_hw_timestamp;
		*rx_sw_ts = meta->rx_sw_timestamp;
	} else {
		*rx_hw_ts = 0;
		*rx_sw_ts = 0;
	}
}

unsigned int xdp_receive_frames(struct xdp_socket *xsk, size_t frame_length, bool mirror_enabled,
				int (*receive_function)(void *data, unsigned char *, size_t),
				void *data, const struct xdp_tx_time *tx_time)
{
	uint32_t idx_rx = 0, idx_tx = 0, idx_fq = 0, len;
	unsigned int received, i;
	unsigned char *packet;
	uint64_t addr, orig;
	int ret;

	/* Receive frames when in busy polling mode */
	if (xsk->busy_poll_mode)
		recvfrom(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL);

	/* Check for received frames */
	received = xsk_ring_cons__peek(&xsk->rx, XDP_BATCH_SIZE, &idx_rx);
	if (!received) {
		if (xsk_ring_prod__needs_wakeup(&xsk->umem.fq))
			recvfrom(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, NULL);
		return 0;
	}

	/*
	 * For mirror reserve space in Tx queue to re-transmit the frames. Otherwise, recycle the Rx
	 * frames immediately.
	 */
	if (mirror_enabled) {
		/* Reserve space in Tx ring */
		ret = xsk_ring_prod__reserve(&xsk->tx, received, &idx_tx);
		while (ret != received) {
			if (ret < 0)
				log_message(LOG_LEVEL_ERROR,
					    "XdpRx: xsk_ring_prod__reserve() failed\n");

			if (xsk->busy_poll_mode || xsk_ring_prod__needs_wakeup(&xsk->tx))
				recvfrom(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL,
					 NULL);
			ret = xsk_ring_prod__reserve(&xsk->tx, received, &idx_tx);
		}
	} else {
		/* Reserve space in fill queue */
		ret = xsk_ring_prod__reserve(&xsk->umem.fq, received, &idx_fq);
		while (ret != received) {
			if (ret < 0)
				log_message(LOG_LEVEL_ERROR,
					    "XdpRx: xsk_ring_prod__reserve() failed\n");

			if (xsk->busy_poll_mode || xsk_ring_prod__needs_wakeup(&xsk->umem.fq))
				recvfrom(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL,
					 NULL);
			ret = xsk_ring_prod__reserve(&xsk->umem.fq, received, &idx_fq);
		}
	}

	for (i = 0; i < received; ++i) {
		/* Get the packet */
		addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
		len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;
		orig = xsk_umem__extract_addr(addr);

		/* Parse it */
		addr = xsk_umem__add_offset_to_addr(addr);
		packet = xsk_umem__get_data(xsk->umem.buffer, addr);
		receive_function(data, packet, len);

		if (mirror_enabled) {
			struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&xsk->tx, idx_tx++);

			/* Store received frame in Tx ring */
			tx_desc->addr = orig;
			tx_desc->len = frame_length;

			/* Prepare tx desc with Tx Time or Tx HW timestamp */
			if (xsk->tx_time_mode || xsk->tx_hwtstamp_mode)
				xdp_prepare_tx_desc(xsk, tx_desc, tx_time, i, false);
		} else {
			/* Move buffer back to fill queue */
			*xsk_ring_prod__fill_addr(&xsk->umem.fq, idx_fq++) = orig;
		}
	}

	if (mirror_enabled) {
		xsk_ring_cons__release(&xsk->rx, received);
	} else {
		xsk_ring_prod__submit(&xsk->umem.fq, received);
		xsk_ring_cons__release(&xsk->rx, received);
	}

	return received;
}
