#!/bin/bash
#
# Copyright (C) 2021,2022 Linutronix GmbH
# Author Kurt Kanzenbach <kurt@linutronix.de>
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Setup the Tx and Rx traffic flows for Intel i225.
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
[ -z $CYCLETIME_NS ] && CYCLETIME_NS="1000000"                   # default: 1ms
[ -z $BASETIME ] && BASETIME=$(date '+%s000000000' -d '-30 sec') # default: now - 30s

load_kernel_modules

setup_threaded_napi "${INTERFACE}"

igc_start "${INTERFACE}"

#
# For testing the hardware platform use a different schedule: The Profinet spec
# allows to utililze up to 90% for real time streams. In order to test the XDP
# performance use 75/25 split. Keep 25% for RTA, PTP, LLDP, DCP and UDP traffic.
#
ENTRY1_NS=$(echo "$CYCLETIME_NS * 12.5 / 100" | bc) # TSN High
ENTRY2_NS=$(echo "$CYCLETIME_NS * 12.5 / 100" | bc) # TSN Low
ENTRY3_NS=$(echo "$CYCLETIME_NS * 25 / 100" | bc)   # RTC
ENTRY4_NS=$(echo "$CYCLETIME_NS * 50 / 100" | bc)   # Everything else

#
# Tx Assignment with Qbv and full hardware offload.
#
# PCP 6 - Queue 0 - TSN High
# PCP 5 - Queue 1 - TSN Low
# PCP 4 - Queue 2 - RTC
# PCP 3/2/1/7 - Queue 3 - RTA / LLDP / DCP / PTP / UDP
#
tc qdisc replace dev ${INTERFACE} handle 100 parent root taprio num_tc 4 \
  map 3 3 3 3 3 2 1 0 3 3 3 3 3 3 3 3 \
  queues 1@0 1@1 1@2 1@3 \
  base-time ${BASETIME} \
  sched-entry S 0x01 ${ENTRY1_NS} \
  sched-entry S 0x02 ${ENTRY2_NS} \
  sched-entry S 0x04 ${ENTRY3_NS} \
  sched-entry S 0xf8 ${ENTRY4_NS} \
  flags 0x02

#
# Rx Queues Assignment.
#
# Rx Q 3 - All Traffic
# Rx Q 2 - RTC
# Rx Q 1 - TSN Low
# Rx Q 0 - TSN High
#
RXQUEUES=(3 0 1 2 3 3 3 3 3 3)
igc_rx_queues_assign "${INTERFACE}" RXQUEUES

igc_end "${INTERFACE}"

setup_irqs "${INTERFACE}"

exit 0
