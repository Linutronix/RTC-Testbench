// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2025 Linutronix GmbH
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

		for (int i = 0; i < NUM_FRAME_TYPES; i++) {
			const char *name = i == GENERICL2_FRAME_TYPE
						   ? app_config.classes[GENERICL2_FRAME_TYPE].name
						   : stat_frame_type_to_string(i);
			const struct statistics *stat = &global_statistics[i];
			uint64_t errors;

			errors = stat->frame_id_errors + stat->out_of_order_errors +
				 stat->payload_errors;

			if (config_is_traffic_class_active(stat_frame_type_to_string(i))) {
				printf("%-8s: Tx:%10" PRIu64 " Rx:%10" PRIu64
				       " RttMin[us]:%10" PRIu64
				       " RttAvg[us]:%10lf RttMax[us]:%10" PRIu64 " Err:%8" PRIu64
				       " Outlier:%8" PRIu64 "\n",
				       name, stat->frames_sent, stat->frames_received,
				       stat->round_trip_min, stat->round_trip_avg,
				       stat->round_trip_max, errors, stat->round_trip_outliers);
				++active;
			}
		}

		printf("-------------------------------------------------------------------"
		       "-------------\n");

		printf("\033[%dA", active + 1);

		sleep(1);
	}
}
