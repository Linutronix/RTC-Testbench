// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/*
 * Copyright (C) Intel Corporation
 * Author Faizal Abdul Rahim <faizal.abdul.rahim@linux.intel.com>
 */

#include "xdp_metadata.h"
#include "app_config.h"

extern int bpf_xdp_metadata_rx_timestamp(const struct xdp_md *ctx, __u64 *timestamp) __ksym;

void populate_rx_timestamp(struct xdp_md *ctx)
{
#ifdef RX_TIMESTAMP
	struct xdp_meta *meta;
	void *data;
	int err;

	err = bpf_xdp_adjust_meta(ctx, -(int)sizeof(struct xdp_meta));
	if (err)
		return;

	data = (void *)(long)ctx->data;
	meta = (struct xdp_meta *)(long)ctx->data_meta;
	/* Bounds check */
	if ((void *)(meta + 1) > data)
		return;

	err = bpf_xdp_metadata_rx_timestamp(ctx, &meta->rx_hw_timestamp);
	meta->rx_sw_timestamp = bpf_ktime_get_tai_ns();
	if (err) {
		meta->rx_hw_timestamp_err = err;
		meta->hint_valid = 0;
	} else {
		meta->hint_valid |= XDP_META_FIELD_TS;
	}
#endif
}
