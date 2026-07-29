#!/bin/bash
#
# Copyright (C) 2026 Linutronix GmbH
# Author Kurt Kanzenbach <kurt@linutronix.de>
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Setup the Tx and Rx traffic flows for Intel i210 for Profinet scenario.
#

set -e

source ../lib/common.sh
source ../lib/igb.sh

#
# Command line arguments.
#
INTERFACE=$1

[ -z $INTERFACE ] && INTERFACE="enp2s0" # default: enp2s0

load_kernel_modules

setup_threaded_napi "${INTERFACE}"

igb_start "${INTERFACE}"

#
# Tx Assignment with SP and hardware offload.
#
tc qdisc replace dev ${INTERFACE} handle 100 parent root mqprio num_tc 4 \
  map 3 3 2 2 0 1 1 1 \
  queues 1@0 1@1 1@2 1@3 \
  hw 1

#
# Rx Queues Assignment.
#
# Rx Q 3 - All Traffic
# Rx Q 2 - RTC
# Rx Q 1 - TSN Low
# Rx Q 0 - TSN High
#
RXQUEUES=(3 0 1 2 3 3 3 3 3 3)
igb_rx_queues_assign "${INTERFACE}" RXQUEUES

igb_end "${INTERFACE}"

setup_irqs "${INTERFACE}"

exit 0
