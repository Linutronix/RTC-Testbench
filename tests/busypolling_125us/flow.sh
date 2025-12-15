#!/bin/bash
#
# Copyright (C) 2024 Linutronix GmbH
# Author Kurt Kanzenbach <kurt@linutronix.de>
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Setup the Tx and Rx traffic flows for Intel i225 for testing XDP busy polling.
#

set -e

source ../lib/common.sh
source ../lib/igc.sh

#
# Command line arguments.
#
INTERFACE=$1
CYCLETIME_NS=$2
BASETIME=$3

[ -z $INTERFACE ] && INTERFACE="enp3s0"                          # default: enp3s0
[ -z $CYCLETIME_NS ] && CYCLETIME_NS="125000"                    # default: 125us
[ -z $BASETIME ] && BASETIME=$(date '+%s000000000' -d '-30 sec') # default: now - 30s

load_kernel_modules

napi_defer_hard_irqs "${INTERFACE}" "${CYCLETIME_NS}"

igc_start "${INTERFACE}"

#
# Split traffic between TSN streams, priority and everything else.
#
ENTRY1_NS="32000" # RTC
ENTRY2_NS="32000" # TSN Streams / Prio
ENTRY3_NS="61000" # Everything else

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
