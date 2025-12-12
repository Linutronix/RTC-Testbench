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
# load_kernel_modules()
#
# Load require kernel modules for Tx scheduling.
#
load_kernel_modules() {
  modprobe sch_taprio || true
  modprobe sch_mqprio || true
  modprobe sch_etf || true
}

#
# napi_defer_hard_irqs($interface, $cycle_time_ns)
#
# Configure napi_defer_hard_irqs and gro_flush_timeout for busy polling:
#  - napi_defer_hard_irqs: How often will the NAPI processing be defered?
#  - gro_flush_timeout: Timeout when the kernel will take over NAPI processing.
#    Has to be greather than the $cycle_time_ns
#
napi_defer_hard_irqs() {
  local interface=$1
  local cycle_time=$2
  local gro_flush_timeout

  gro_flush_timeout=$(echo "$cycle_time * 2" | bc)
  echo 10 >"/sys/class/net/${interface}/napi_defer_hard_irqs"
  echo "${gro_flush_timeout}" >"/sys/class/net/${interface}/gro_flush_timeout"
}

#
# napi_defer_hard_irqs_queue($napictl, $interface, $cycle_time_ns, $queue)
#
# Same as napi_defer_hard_irqs(), but does it only for a specific queue.
#
napi_defer_hard_irqs_queue() {
  local napictl=$1
  local interface=$2
  local cycle_time=$3
  local queue=$4
  local gro_flush_timeout

  if ! [ -x "$napictl" ]; then
    echo "$napictl not found!"
    return 1
  fi

  gro_flush_timeout=$(echo "$cycle_time * 2" | bc)
  $napictl -i "${interface}" -q "${queue}" -d 10 -g "${gro_flush_timeout}"
}

#
# setup_threaded_napi($interface)
#
# Enable NAPI threaded mode: This allows the NAPI processing being executed in dedicated kernel
# threads instead of using NET_RX soft irq. Using these allows to prioritize the Rx processing in
# accordance to use case.
#
# Increase NAPI thread priorities. By default, every NAPI thread uses SCHED_OTHER.
#
setup_threaded_napi() {
  local interface=$1
  local napithreads

  echo 1 >"/sys/class/net/${interface}/threaded"

  napithreads=$(ps aux | grep napi | grep "${interface}" | awk '{ print $2; }')
  for task in ${napithreads}; do
    chrt -p -f 85 "$task"
  done
}

#
# setup_irqs($interface)
#
# Increase IRQ thread priorities. By default, every IRQ thread has priority 50.
#
setup_irqs() {
  local interface=$1
  local irqthreads

  irqthreads=$(ps aux | grep irq | grep "${interface}" | awk '{ print $2; }')

  for task in ${irqthreads}; do
    chrt -p -f 85 "$task"
  done
}
