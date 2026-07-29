#!/bin/bash
#
# Copyright (C) 2026 Linutronix GmbH
# Author Kurt Kanzenbach <kurt@linutronix.de>
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Setup the Tx and Rx traffic flows for Intel i225 for profinet scenario.
#

set -e

source ../lib/common.sh
source ../lib/igc.sh

#
# Command line arguments.
#
INTERFACE=$1

[ -z $INTERFACE ] && INTERFACE="enp3s0" # default: enp3s0

load_kernel_modules

setup_threaded_napi "${INTERFACE}"

igc_start "${INTERFACE}"

tc qdisc replace dev ${INTERFACE} handle 100 parent root mqprio num_tc 4 \
  map 3 3 2 2 0 1 1 1 \
  queues 1@0 1@1 1@2 1@3 \
  hw 0

RXQUEUES=(3 0 1 2 3 3 3 3 3 3)
igc_rx_queues_assign "${INTERFACE}" RXQUEUES

igc_end "${INTERFACE}"

setup_irqs "${INTERFACE}"

exit 0
