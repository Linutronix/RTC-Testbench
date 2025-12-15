#!/bin/bash
#
# Copyright (C) 2023 Linutronix GmbH
# Author Kurt Kanzenbach <kurt@linutronix.de>
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Setup the Tx and Rx traffic flows for Intel i225 for PROFINET RT scenario.
#

set -e

source ../lib/common.sh
source ../lib/igc.sh

#
# Command line arguments.
#
INTERFACE=$1

[ -z $INTERFACE ] && INTERFACE="enp3s0"      # default: enp3s0
BASETIME=$(date '+%s000000000' -d '-30 sec') # default: now - 30s

load_kernel_modules

setup_threaded_napi "${INTERFACE}"

igc_start "${INTERFACE}"

#
# Tx Assignment with Qbv and full hardware offload.
#
# Tx Q 0 - RTC
# Tx Q 1 - RTA
# Tx Q 2 - DCP, LLDP, UDP High
# Tx Q 3 - Everything else
#
tc qdisc replace dev ${INTERFACE} handle 100 parent root taprio num_tc 4 \
  map 3 3 3 3 3 2 1 0 3 3 3 3 3 3 3 3 \
  queues 1@0 1@1 1@2 1@3 \
  base-time ${BASETIME} \
  sched-entry S 0x01 100000 \
  sched-entry S 0x02 100000 \
  sched-entry S 0x04 400000 \
  sched-entry S 0x08 400000 \
  flags 0x02

#
# Rx Queues Assignment.
#
# Rx Q 0 - RTC
# Rx Q 1 - RTA
# Rx Q 2 - DCP, LLDP, UDP High
# Rx Q 3 - Everything else
#
RXQUEUES=(2 2 2 0 1 2 2 3 2 2)
igc_rx_queues_assign "${INTERFACE}" RXQUEUES

igc_end "${INTERFACE}"

setup_irqs "${INTERFACE}"

exit 0
