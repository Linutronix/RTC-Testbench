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
[ -z $CYCLETIME_NS ] && CYCLETIME_NS="1000000"                   # default: 125us
[ -z $BASETIME ] && BASETIME=$(date '+%s000000000' -d '-30 sec') # default: now - 30s

load_kernel_modules

napi_defer_hard_irqs "${INTERFACE}" "${CYCLETIME_NS}"

igc_start "${INTERFACE}"

#
# Split traffic between TSN streams, priority and everything else.
#
ENTRY1_NS="500000" # TSN Streams / Prio
ENTRY2_NS="500000" # Everything else

#
# Tx Assignment with Qbv and full hardware offload.
#
# PCP 6   - Tx Q 1 - TSN High
# PCP X   - Tx Q 0 - Everything else
#
tc qdisc replace dev ${INTERFACE} handle 100 parent root taprio num_tc 2 \
  map 0 0 0 0 0 0 1 0 0 0 0 0 0 0 0 0 \
  queues 1@0 1@1 \
  base-time ${BASETIME} \
  sched-entry S 0x02 ${ENTRY1_NS} \
  sched-entry S 0x03 ${ENTRY2_NS} \
  flags 0x02

#
# Rx Queues Assignment.
#
# PCP 6   - Rx Q 1 - TSN High
# PCP X   - Rx Q 0 - Everything else
#
RXQUEUES=(0 1 0 0 0 0 0 0 0 0)
igc_rx_queues_assign "${INTERFACE}" RXQUEUES

igc_end "${INTERFACE}"

setup_irqs "${INTERFACE}"

exit 0
