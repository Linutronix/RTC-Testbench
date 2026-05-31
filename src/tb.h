/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2026 Linutronix GmbH
 */

#ifndef TB_H
#define TB_H

#include <stdbool.h>

#include "stat.h"

struct tb_startup_mode {
	const char *binary_name;
	enum log_stat_options stat_mode;
	bool use_histogram;
	bool is_mirror;
};

void tb_startup(int argc, char *argv[], struct tb_startup_mode *mode);

#endif /* TB_H */
