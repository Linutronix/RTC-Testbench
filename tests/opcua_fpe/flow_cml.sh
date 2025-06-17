#!/bin/bash
#
# Copyright (C) 2023-2025 Linutronix GmbH
# Author Kurt Kanzenbach <kurt@linutronix.de>
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Setup the Tx and Rx traffic flows for Intel i225/i226 for OpcUa scenario with Frame Preemption
# (FPE).
#
# Note: The FPE statistics are not included in ethtool -S. Use ethtool --include-statistics
# --show-mm <inf> instead.
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

#
# Tx Assignment with Qbv and full hardware offload.
#
# PCP 6   - Tx Q 3 - TSN High / OpcUa
# PCP 5   - Tx Q 2 - TSN Low
# PCP 4   - Tx Q 1 - RTC
# PCP 3/X - Tx Q 0 - RTA and Everything else
#
tc qdisc replace dev ${INTERFACE} handle 100 parent root mqprio num_tc 4 \
  map 0 0 0 0 0 1 2 3 0 0 0 0 0 0 0 0 \
  queues 1@0 1@1 1@2 1@3 \
  fp P P P E \
  hw 1

#
# Enable FPE.
#
ethtool --set-mm ${INTERFACE} pmac-enabled on tx-enabled on verify-enabled on

#
# Rx Queues Assignment.
#
# Rx Q 0 - All Traffic
# Rx Q 1 - RTC
# Rx Q 2 - TSN Low
# Rx Q 3 - TSN High / OpcUa
#
RXQUEUES=(0 3 2 1 0 0 0 0 0 0)
igc_rx_queues_assign "${INTERFACE}" RXQUEUES

igc_end "${INTERFACE}"

setup_irqs "${INTERFACE}"

exit 0
