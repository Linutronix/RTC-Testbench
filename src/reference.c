// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2020-2026 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#include <stdbool.h>
#include <stdlib.h>

#include "tb.h"

int main(int argc, char *argv[])
{
	struct tb_startup_mode mode = {
		.binary_name = "reference",
		.stat_mode = LOG_REFERENCE,
		.use_histogram = true,
		.is_mirror = false,
	};

	tb_startup(argc, argv, &mode);

	return EXIT_SUCCESS;
}
