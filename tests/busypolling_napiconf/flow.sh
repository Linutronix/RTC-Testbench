#!/bin/bash
#
# Copyright (C) 2023-2025 Linutronix GmbH
# Author Kurt Kanzenbach <kurt@linutronix.de>
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Setup the Tx and Rx traffic flows for Intel i226 for testing XDP busy polling.
#

set -e

source ../lib/common.sh
source ../lib/igc.sh

#
# Command line arguments.
#
INTERFACE=$1

#
# Config.
#
CYCLETIME_NS="1000000"
BASETIME=$(date '+%s000000000' -d '-30 sec')
NAPICTL="../../build/napictl"

[ -z $INTERFACE ] && INTERFACE="enp3s0" # default: enp3s0

load_kernel_modules

#
# Configure napi-defer-hard-irqs and gro-flush-timeout for queue 0.
#
napi_defer_hard_irqs_queue "${NAPICTL}" "${INTERFACE}" "${CYCLETIME_NS}" 0

igc_start "${INTERFACE}"

#
# Split traffic between TSN streams, priority and everything else.
#
ENTRY1_NS=$(echo "$CYCLETIME_NS * 50 / 100" | bc) # RTC
ENTRY2_NS=$(echo "$CYCLETIME_NS * 25 / 100" | bc) # TSN Streams / Prio
ENTRY3_NS=$(echo "$CYCLETIME_NS * 25 / 100" | bc) # Everything else

#
# Tx Assignment with Qbv and full hardware offload.
#
# PCP 4   - Rx Q 0 - RTC
# PCP 6/5 - Rx Q 1 - TSN Streams / Prio
# PCP X   - Rx Q 2 - Everything else
#
tc qdisc replace dev ${INTERFACE} handle 100 parent root taprio num_tc 3 \
  map 2 2 2 2 2 2 1 0 2 2 2 2 2 2 2 2 \
  queues 1@0 1@1 2@2 \
  base-time ${BASETIME} \
  sched-entry S 0x01 ${ENTRY1_NS} \
  sched-entry S 0x02 ${ENTRY2_NS} \
  sched-entry S 0x04 ${ENTRY3_NS} \
  flags 0x02

#
# Rx Queues Assignment.
#
# PCP 4   - Rx Q 0 - RTC
# PCP 6/5 - Rx Q 1 - TSN Streams / Prio
# PCP X   - Rx Q 2 - Everything else
#
RXQUEUES=(2 1 1 0 2 2 2 2 1 1)
igc_rx_queues_assign "${INTERFACE}" RXQUEUES

igc_end "${INTERFACE}"

setup_irqs "${INTERFACE}"

exit 0
