# -*- mode: shell-script; sh-shell: bash -*-
#
# Copyright (C) 2020-2025 Linutronix GmbH
# Author Kurt Kanzenbach <kurt@linutronix.de>
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Test setup library.
#

#
# igc_start($interface)
#
igc_start() {
  local interface=$1

  #
  # Disable VLAN Rx offload for eBPF XDP programs.
  #
  ethtool -K "${interface}" rx-vlan-offload off

  #
  # Reduce link speed, because igc is capable of 2.5G, too.
  #
  ethtool -s "${interface}" speed 1000 autoneg on duplex full

  #
  # Increase the number of Rx and Tx queues in case of $num_cpus < 4.
  #
  ethtool -L "${interface}" combined 4

  #
  # Disable Energy Efficient Ethernet (EEE).
  #
  ethtool --set-eee "${interface}" eee off
}

#
# igc_end($interface)
#
igc_end() {
  local interface=$1

  #
  # Increase Tx and Rx ring sizes.
  #
  ethtool -G "${interface}" rx 4096 tx 4096
}

#
# igc_rx_queues_assign($interface, @rx_queues)
#
# Rx queues assignment based on PCP values and EtherType.
#
igc_rx_queues_assign() {
  local interface=$1
  local -n rx_queues=$2
  local len

  len=${#rx_queues[@]}

  if [ "$len" -ne 10 ]; then
    echo "igc_rx_queues_assign: rx_queues array len has to be 10!"
    return
  fi

  ethtool -K "${interface}" ntuple on

  # PCP 7
  ethtool -N "${interface}" flow-type ether vlan 0xe000 m 0x1fff action "${rx_queues[0]}"

  # PCP 6
  ethtool -N "${interface}" flow-type ether vlan 0xc000 m 0x1fff action "${rx_queues[1]}"

  # PCP 5
  ethtool -N "${interface}" flow-type ether vlan 0xa000 m 0x1fff action "${rx_queues[2]}"

  # PCP 4
  ethtool -N "${interface}" flow-type ether vlan 0x8000 m 0x1fff action "${rx_queues[3]}"

  # PCP 3
  ethtool -N "${interface}" flow-type ether vlan 0x6000 m 0x1fff action "${rx_queues[4]}"

  # PCP 2
  ethtool -N "${interface}" flow-type ether vlan 0x4000 m 0x1fff action "${rx_queues[5]}"

  # PCP 1
  ethtool -N "${interface}" flow-type ether vlan 0x2000 m 0x1fff action "${rx_queues[6]}"

  # PCP 0
  ethtool -N "${interface}" flow-type ether vlan 0x0000 m 0x1fff action "${rx_queues[7]}"

  #
  # PTP and LLDP are transmitted untagged. Steer them via EtherType.
  #
  ethtool -N "${interface}" flow-type ether proto 0x88f7 action "${rx_queues[8]}"
  ethtool -N "${interface}" flow-type ether proto 0x88cc action "${rx_queues[9]}"
}
