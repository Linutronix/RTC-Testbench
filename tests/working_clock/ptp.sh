#!/bin/bash
#
# Copyright (C) 2021-2026 Linutronix GmbH
# Author Kurt Kanzenbach <kurt@linutronix.de>
#
# SPDX-License-Identifier: BSD-2-Clause
#
# This testcase has two time domains:
#
#   - Global time:
#       Synchronized by NTP e.g., with chrony. Corresponds to CLOCK_REALTIME and CLOCK_TAI in Linux.
#
#   - Working clock:
#       High precision clock synchronized by gPTP used for real time scheduling. Corresponds to
#       CLOCK_AUX0 in Linux.
#
# The point is CLOCK_AUX0 is an arbitrary time domain (e.g. starting at zero), whereas
# CLOCK_REALTIME points to valid UTC time. Both time domains are independent of each other.
#
# Note 1: This test case requires an update-to-date Linux kernel >= 7.1 for clock_gettime(2) and
# clock_nanosleep(2) support on CLOCK_AUX*.
#
# Note 2: This test case requires an patched version of phc2sys. Code is available at
# https://github.com/mlichvar/linuxptp.git branch=staging.
#

set -e

cd "$(dirname "$0")"

# Interface
INTERFACE=$1
[ -z $INTERFACE ] && INTERFACE="eth0"

# Kill already running daemons
pkill ptp4l || true
pkill phc2sys || true

# Start ptp with 802.1AS-2011 endstation profile
ptp4l -2 -H -i ${INTERFACE} --socket_priority=4 --tx_timestamp_timeout=40 -f /etc/gPTP.cfg &

# Wait for ptp4l
sleep 10

# Enable CLOCK_AUX0 in kernel timekeeping first
echo 1 >/sys/kernel/time/aux_clocks/0/aux_clock_enable

# Synchronize CLOCK_AUX0 to network time
phc2sys -s ${INTERFACE} -c CLOCK_AUX0 --step_threshold=1 --transportSpecific=1 -w &

exit 0
