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

load_kernel_modules

setup_threaded_napi "${INTERFACE}"

stmmac_start "${INTERFACE}"

#
# Tx Assignment with SP.
#
# Tx Q 0 - Everything else
# Tx Q 1 - RTC
#
tc qdisc replace dev ${INTERFACE} handle 100 parent root mqprio num_tc 2 \
  map 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0 0 \
  queues 1@0 1@1 \
  hw 1

#
# Enable Tx launch time support for TC 1.
#
tc qdisc replace dev ${INTERFACE} parent 100:2 etf \
  clockid CLOCK_TAI \
  delta 500000 \
  offload

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
