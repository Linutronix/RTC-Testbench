#!/bin/bash
#
# Copyright (C) 2024 Linutronix GmbH
# Author Kurt Kanzenbach <kurt@linutronix.de>
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Setup the Tx and Rx traffic flows for Intel i210 for testing XDP busy polling.
#

set -e

source ../lib/common.sh
source ../lib/igb.sh

#
# Command line arguments.
#
INTERFACE=$1
CYCLETIME_NS=$2
BASETIME=$3

[ -z $INTERFACE ] && INTERFACE="enp2s0"                          # default: enp2s0
[ -z $CYCLETIME_NS ] && CYCLETIME_NS="1000000"                   # default: 1ms
[ -z $BASETIME ] && BASETIME=$(date '+%s000000000' -d '-30 sec') # default: now - 30s

load_kernel_modules

napi_defer_hard_irqs "${INTERFACE}" "${CYCLETIME_NS}"

igb_start "${INTERFACE}"

#
# Tx Assignment with strict priority.
#
# PCP 4 - Rx Q 0 - RTC
# PCP X - Rx Q 1 - Everything else
#
tc qdisc replace dev ${INTERFACE} handle 100 parent root mqprio num_tc 2 \
  map 1 1 1 1 1 1 1 0 1 1 1 1 1 1 1 1 \
  queues 1@0 1@1 \
  hw 0

#
# Rx Queues Assignment.
#
# PCP 4 - Rx Q 0 - RTC
# PCP X - Rx Q 1 - Everything else
#
RXQUEUES=(1 1 1 0 1 1 1 1 1 1)
igb_rx_queues_assign "${INTERFACE}" RXQUEUES

igb_end "${INTERFACE}"

setup_irqs "${INTERFACE}"

exit 0
