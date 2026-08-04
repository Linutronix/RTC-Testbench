#!/bin/bash
#
# Copyright (C) 2026 Linutronix GmbH
# Author Kurt Kanzenbach <kurt@linutronix.de>
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Setup the Tx and Rx traffic flows for st32mp257 stmmac for PROFINET RT scenario.
#

set -e

source ../../lib/common.sh
source ../../lib/stmmac.sh

#
# Command line arguments.
#
INTERFACE=$1

[ -z $INTERFACE ] && INTERFACE="end0"
BASETIME=$(date '+%s000000000' -d '60 sec')

load_kernel_modules

CYCLETIME_NS="1000000"
napi_defer_hard_irqs "${INTERFACE}" "${CYCLETIME_NS}"

stmmac_start "${INTERFACE}"

#
# Tx Assignment with Qbv and full hardware offload: 20% RT, 80% non-RT.
#
# Tx Q 0 - Everything else
# Tx Q 1 - RTC
#
tc qdisc replace dev ${INTERFACE} handle 100 parent root taprio num_tc 2 \
  map 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0 0 \
  queues 1@0 1@1 \
  base-time ${BASETIME} \
  sched-entry S 0x02 200000 \
  sched-entry S 0x01 800000 \
  flags 0x02

#
# Rx Queues Assignment.
#
# Rx Q 0 - Everything else
# Rx Q 1 - RTC
#
RXQUEUES=(0 0 0 1 0 0 0 0 0 0)
stmmac_rx_queues_assign "${INTERFACE}" RXQUEUES

stmmac_end "${INTERFACE}"

setup_irqs "${INTERFACE}"

exit 0
