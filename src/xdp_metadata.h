// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/*
 * Copyright (C) Intel Corporation
 * Author Faizal Abdul Rahim <faizal.abdul.rahim@linux.intel.com>
 */

#ifndef XDP_METADATA_H
#define XDP_METADATA_H

#ifndef BIT
#define BIT(nr) (1 << (nr))
#endif

enum xdp_meta_field {
	XDP_META_FIELD_TS = BIT(0),
};

struct xdp_meta {
	union {
		__u64 rx_hw_timestamp;
		__s32 rx_hw_timestamp_err;
	};
	__u64 rx_sw_timestamp;
	enum xdp_meta_field hint_valid;
};

#endif /* XDP_METADATA_H */
