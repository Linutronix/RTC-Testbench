// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2020-2026 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "net.h"
#include "profinet.h"
#include "rta_thread.h"
#include "tc.h"

static void rta_initialize_frame(struct thread_context *ctx, unsigned char *frame_data,
				 size_t frame_length, const unsigned char *source,
				 const unsigned char *destination)
{
	const struct traffic_class_config *conf = ctx->conf;

	initialize_profinet_frame(conf->security_mode, frame_data, frame_length, source,
				  destination, conf->payload_pattern, conf->payload_pattern_length,
				  conf->vid | conf->pcp << VLAN_PCP_SHIFT, ctx->frame_id);
}

int rta_threads_create(struct thread_context *ctx)
{
	struct traffic_class_config *conf;
	int ret;

	if (!config_is_tc_active(RTA_FRAME_TYPE))
		return 0;

	ctx->conf = conf = &app_config.classes[RTA_FRAME_TYPE];
	ctx->frame_type = RTA_FRAME_TYPE;
	ctx->traffic_class = stat_frame_type_to_string(RTA_FRAME_TYPE);
	ctx->frame_id = conf->security_mode == SECURITY_MODE_NONE ? RTA_FRAMEID : RTA_SEC_FRAMEID;

	ctx->desc = calloc(1, sizeof(*ctx->desc));
	if (!ctx->desc) {
		fprintf(stderr, "Failed to allocate %s TC description!\n", ctx->traffic_class);
		return -ENOMEM;
	}

	ctx->desc->tx_model = TC_TX_BURST;
	ctx->desc->ops.initialize_frame = rta_initialize_frame;
	ctx->desc->ops.receive_frame = receive_profinet_frame;
	ctx->desc->ops.create_socket = create_rta_socket;

	if (conf->xdp_enabled) {
		ctx->desc->ops.tx_thread = tc_xdp_tx_thread;
		ctx->desc->ops.rx_thread = tc_xdp_rx_thread;
	} else {
		ctx->desc->ops.tx_thread = tc_tx_thread;
		ctx->desc->ops.rx_thread = tc_rx_thread;
	}

	ret = tc_threads_create(ctx);
	if (ret)
		free(ctx->desc);

	return ret;
}

void rta_threads_free(struct thread_context *thread_context)
{
	tc_threads_free(thread_context);
}

void rta_threads_wait_for_finish(struct thread_context *thread_context)
{
	tc_threads_wait_for_finish(thread_context);
}
