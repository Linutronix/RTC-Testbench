#!/bin/bash
#
# Copyright (C) 2021 Linutronix GmbH
# Author Kurt Kanzenbach <kurt@linutronix.de>
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Setup the Rx and Tx traffic flows on Intel Elkhart Lake.
#
# Rx steering is based on PCP values. Tx steering is based on socket priorities
# which are mapped to traffic classes and to timeslots accordingly.
#

set -e

source ../../../lib/common.sh
source ../../../lib/stmmac.sh

#
# Command line arguments.
#
INTERFACE=$1
CYCLETIME_NS=$2
BASETIME=$3

[ -z $INTERFACE ] && INTERFACE="enp0s29f2"                      # default: enp0s29f2
[ -z $CYCLETIME_NS ] && CYCLETIME_NS="1000000"                  # default: 1ms
[ -z $BASETIME ] && BASETIME=$(date '+%s000000000' -d '60 sec') # default: now + 60s

load_kernel_modules

setup_threaded_napi "${INTERFACE}"

stmmac_start "${INTERFACE}"

#
# Qbv configuration.
#
ENTRY1_NS=$(echo "$CYCLETIME_NS * 12.5 / 100" | bc) # TSN High
ENTRY2_NS=$(echo "$CYCLETIME_NS * 12.5 / 100" | bc) # TSN Low
ENTRY3_NS=$(echo "$CYCLETIME_NS * 12.5 / 100" | bc) # RT
ENTRY4_NS=$(echo "$CYCLETIME_NS * 12.5 / 100" | bc) # RT
ENTRY5_NS=$(echo "$CYCLETIME_NS * 50 / 100" | bc)   # Non-RT

#
# Tx Assignment with Qbv and full hardware offload.
#
# PCP 0 - Queue 0 - UDP Low
# PCP 1 - Queue 1 - UDP High
# PCP 2 - Queue 2 - DCP
# PCP 3 - Queue 3 - RTA
# PCP 4 - Queue 5 - RTC
# PCP 5 - Queue 6 - TSN LOW
# PCP 6 - Queue 7 - TSN HIGH
# PCP 7 - Queue 4 - PTP/LLDP
#
tc qdisc replace dev ${INTERFACE} handle 100 parent root taprio num_tc 8 \
  map 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 \
  queues 1@0 1@1 1@2 1@3 1@4 1@5 1@6 1@7 \
  base-time ${BASETIME} \
  sched-entry S 0x80 ${ENTRY1_NS} \
  sched-entry S 0x40 ${ENTRY2_NS} \
  sched-entry S 0x20 ${ENTRY3_NS} \
  sched-entry S 0x10 ${ENTRY4_NS} \
  sched-entry S 0x0f ${ENTRY5_NS} \
  flags 0x02

#
# Create VLAN interfaces.
#
ip link add link ${INTERFACE} name ${INTERFACE}.100 type vlan id 100
ip link add link ${INTERFACE} name ${INTERFACE}.200 type vlan id 200
ip link add link ${INTERFACE} name ${INTERFACE}.300 type vlan id 300
ip link add link ${INTERFACE} name ${INTERFACE}.400 type vlan id 400

ip link set ${INTERFACE}.100 up
ip link set ${INTERFACE}.200 up
ip link set ${INTERFACE}.300 up
ip link set ${INTERFACE}.400 up

#
# Rx Assignment.
#
# PCP 0 - Queue 0 - UDP Low
# PCP 1 - Queue 1 - UDP High
# PCP 2 - Queue 2 - DCP
# PCP 3 - Queue 3 - RTA
# PCP 4 - Queue 5 - RTC
# PCP 5 - Queue 6 - TSN LOW
# PCP 6 - Queue 7 - TSN HIGH
# PCP 7 - Queue 4 - PTP/LLDP
#
RXQUEUES=(4 7 6 5 3 2 1 0 4 4)
stmmac_rx_queues_assign "${INTERFACE}" RXQUEUES

stmmac_end "${INTERFACE}"

setup_irqs "${INTERFACE}"

exit 0
