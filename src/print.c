// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2025-2026 Linutronix GmbH
 * Author Kurt Kanzenbach <kurt@linutronix.de>
 */

#include <stdio.h>
#include <unistd.h>

#include "config.h"
#include "print.h"
#include "stat.h"

volatile int print_stop = 0;

void print_stats(void)
{
	while (!print_stop) {
		struct statistics global_statistics[NUM_FRAME_TYPES];
		int active = 0;

		stat_get_global_stats(global_statistics, sizeof(global_statistics));

		printf("%-9s %12s %12s %11s %11s %11s %9s %9s\n", "Class", "Tx", "Rx", "RttMin[us]",
		       "RttAvg[us]", "RttMax[us]", "Error", "Outlier");

		for (int i = 0; i < NUM_FRAME_TYPES; i++) {
			const struct statistics *stat = &global_statistics[i];
			const char *name = stat_frame_type_to_string(i);
			uint64_t errors;

			if (!config_is_tc_active(i))
				continue;

			errors = stat->frame_id_errors + stat->out_of_order_errors +
				 stat->payload_errors;

			printf("%-9s %12" PRIu64 " %12" PRIu64 " ", name, stat->frames_sent,
			       stat->frames_received);

			/* Min/Avg/Max hold their init values until the first round trip. */
			if (stat->round_trip_count)
				printf("%11" PRIu64 " %11.2lf %11" PRIu64, stat->round_trip_min,
				       stat->round_trip_avg, stat->round_trip_max);
			else
				printf("%11s %11s %11s", "-", "-", "-");

			printf(" %9" PRIu64 " %9" PRIu64 "\n", errors, stat->round_trip_outliers);
			++active;
		}

		printf("-------------------------------------------------------------------"
		       "------------------------\n");

		printf("\033[%dA", active + 2);

		sleep(1);
	}
}
