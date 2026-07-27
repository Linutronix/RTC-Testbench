// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2020-2026 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"
#include "net.h"
#include "profinet.h"
#include "rtc_thread.h"
#include "security.h"
#include "stat.h"
#include "tc.h"
#include "thread.h"
#include "workload.h"

static void rtc_initialize_frame(struct thread_context *ctx, unsigned char *frame_data,
				 size_t frame_length, const unsigned char *source,
				 const unsigned char *destination)
{
	const struct traffic_class_config *conf = ctx->conf;

	initialize_profinet_frame(conf->security_mode, frame_data, frame_length, source,
				  destination, conf->payload_pattern, conf->payload_pattern_length,
				  conf->vid | conf->pcp << VLAN_PCP_SHIFT, ctx->frame_id);
}

int rtc_threads_create(struct thread_context *ctx)
{
	struct traffic_class_config *conf;
	int ret;

	if (!config_is_tc_active(RTC_FRAME_TYPE))
		return 0;

	ctx->conf = conf = &app_config.classes[RTC_FRAME_TYPE];
	ctx->frame_type = RTC_FRAME_TYPE;
	ctx->traffic_class = stat_frame_type_to_string(RTC_FRAME_TYPE);
	ctx->frame_id = conf->security_mode == SECURITY_MODE_NONE ? RTC_FRAMEID : RTC_SEC_FRAMEID;

	ctx->desc = calloc(1, sizeof(*ctx->desc));
	if (!ctx->desc) {
		fprintf(stderr, "Failed to allocate %s TC description!\n", ctx->traffic_class);
		return -ENOMEM;
	}

	ctx->desc->tx_model = TC_TX_CYCLIC;
	ctx->desc->ops.initialize_frame = rtc_initialize_frame;
	ctx->desc->ops.receive_frame = receive_profinet_frame;
	ctx->desc->ops.create_socket = create_rtc_socket;

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

void rtc_threads_free(struct thread_context *ctx)
{
	tc_threads_free(ctx);
}

void rtc_threads_wait_for_finish(struct thread_context *ctx)
{
	tc_threads_wait_for_finish(ctx);
}
