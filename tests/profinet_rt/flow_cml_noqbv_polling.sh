#!/bin/bash
#
# Copyright (C) 2024 Linutronix GmbH
# Author Kurt Kanzenbach <kurt@linutronix.de>
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Setup the Tx and Rx traffic flows for Intel i225 for PROFINET RT scenario.
#

set -e

#
# Command line arguments.
#
INTERFACE=$1

[ -z $INTERFACE ] && INTERFACE="enp3s0"      # default: enp3s0
BASETIME=$(date '+%s000000000' -d '-30 sec') # default: now - 30s

# Load needed kernel modules
modprobe sch_mqprio || true

#
# Configure napi_defer_hard_irqs and gro_flush_timeout for busy polling:
#  - napi_defer_hard_irqs: How often will the NAPI processing be defered?
#  - gro_flush_timeout: Timeout when the kernel will take over NAPI processing.
#    Has to be greather than the $CYCLETIME_NS
#
GRO_FLUSH_TIMEOUT="2000000"
echo 10 >/sys/class/net/${INTERFACE}/napi_defer_hard_irqs
echo ${GRO_FLUSH_TIMEOUT} >/sys/class/net/${INTERFACE}/gro_flush_timeout

#
# Disable VLAN Rx offload.
#
ethtool -K ${INTERFACE} rx-vlan-offload off

#
# Reduce link speed.
#
ethtool -s ${INTERFACE} speed 1000 autoneg on duplex full

#
# Tx Assignment with Strict Priority.
#
# Tx Q 0 - RTC
# Tx Q 1 - RTA
# Tx Q 2 - DCP, LLDP, UDP High
# Tx Q 3 - Everything else
#
tc qdisc replace dev ${INTERFACE} handle 100 parent root mqprio num_tc 4 \
  map 3 3 3 3 3 2 1 0 3 3 3 3 3 3 3 3 \
  queues 1@0 1@1 1@2 1@3 \
  hw 0

#
# Rx Queues Assignment.
#
# Rx Q 0 - RTC
# Rx Q 1 - RTA
# Rx Q 2 - DCP, LLDP, UDP High
# Rx Q 3 - Everything else
#
ethtool -K ${INTERFACE} ntuple on

# RTC: PCP 4 -> Queue 0
ethtool -N ${INTERFACE} flow-type ether vlan 0x8000 m 0x1fff action 0

# RTA: PCP 3 -> Queue 1
ethtool -N ${INTERFACE} flow-type ether vlan 0x6000 m 0x1fff action 1

# PCP 7 -> Queue 2
ethtool -N ${INTERFACE} flow-type ether vlan 0xe000 m 0x1fff action 2

# PCP 6 -> Queue 2
ethtool -N ${INTERFACE} flow-type ether vlan 0xc000 m 0x1fff action 2

# PCP 5 -> Queue 2
ethtool -N ${INTERFACE} flow-type ether vlan 0xa000 m 0x1fff action 2

# PCP 2 -> Queue 2
ethtool -N ${INTERFACE} flow-type ether vlan 0x4000 m 0x1fff action 2

# PCP 1 -> Queue 2
ethtool -N ${INTERFACE} flow-type ether vlan 0x2000 m 0x1fff action 2

# PCP 0 -> Queue 3
ethtool -N ${INTERFACE} flow-type ether vlan 0x0000 m 0x1fff action 3

#
# PTP and LLDP are transmitted untagged. Steer them via EtherType.
#
ethtool -N ${INTERFACE} flow-type ether proto 0x88f7 action 2
ethtool -N ${INTERFACE} flow-type ether proto 0x88cc action 2

#
# Increase Tx and Rx ring sizes.
#
ethtool -G ${INTERFACE} rx 4096 tx 4096

#
# Increase IRQ thread priorities. By default, every IRQ thread has priority 50.
#
IRQTHREADS=$(ps aux | grep irq | grep ${INTERFACE} | awk '{ print $2; }')
for task in ${IRQTHREADS}; do
  chrt -p -f 85 $task
done

exit 0
