#!/bin/bash
#
# Copyright (C) 2023-2025 Linutronix GmbH
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
CYCLETIME_NS=$2
BASETIME=$3

[ -z $INTERFACE ] && INTERFACE="enp3s0"                          # default: enp3s0
[ -z $CYCLETIME_NS ] && CYCLETIME_NS="1000000"                   # default: 1ms
[ -z $BASETIME ] && BASETIME=$(date '+%s000000000' -d '-30 sec') # default: now - 30s

load_kernel_modules

setup_threaded_napi "${INTERFACE}"

igc_start "${INTERFACE}"

#
# Setup egress classification:
#
#  VLAN 100 -> TSN High from container #1 -> Time slot #0
#  VLAN 200 -> TSN High from container #2 -> Time slot #1
#
tc qdisc add dev ${INTERFACE} clsact
tc filter add dev ${INTERFACE} egress protocol 802.1Q flower vlan_id 100 action skbedit priority 7
tc filter add dev ${INTERFACE} egress protocol 802.1Q flower vlan_id 200 action skbedit priority 6

#
# Split traffic between TSN streams, real time and everything else.
#
ENTRY1_NS="64000"  # TSN High #1
ENTRY2_NS="64000"  # TSN High #2
ENTRY3_NS="172000" # Prio
ENTRY4_NS="700000" # Everything else

#
# Tx Assignment with Qbv and full hardware offload.
#
# PCP 6   - Tx Q 0 - TSN High from container #1
# PCP 5   - Tx Q 1 - TSN High from container #2
# PCP 4   - Tx Q 2 - Prio
# PCP 3/X - Tx Q 3 - RTA and Everything else
#
tc qdisc replace dev ${INTERFACE} handle 100 parent root taprio num_tc 4 \
  map 3 3 3 3 3 2 1 0 3 3 3 3 3 3 3 3 \
  queues 1@0 1@1 1@2 1@3 \
  base-time ${BASETIME} \
  sched-entry S 0x01 ${ENTRY1_NS} \
  sched-entry S 0x02 ${ENTRY2_NS} \
  sched-entry S 0x04 ${ENTRY3_NS} \
  sched-entry S 0x08 ${ENTRY4_NS} \
  flags 0x02

#
# Rx Queues Assignment.
#
# Rx Q 3 - All Traffic
# Rx Q 2 - Prio
# Rx Q 1 - TSN High from container #2
# Rx Q 0 - TSN High from container #1
#
RXQUEUES=(3 0 1 2 3 3 3 3 3 3)
igc_rx_queues_assign "${INTERFACE}" RXQUEUES

igc_end "${INTERFACE}"

setup_irqs "${INTERFACE}"

exit 0
