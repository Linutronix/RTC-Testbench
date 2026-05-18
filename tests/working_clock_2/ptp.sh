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
#       Synchronized by gPTP domain A. Corresponds to CLOCK_REALTIME and CLOCK_TAI in Linux.
#
#   - Working clock:
#       High precision clock synchronized by gPTP domain B used for real time scheduling.
#       Corresponds to CLOCK_AUX0 in Linux.
#
# The point is CLOCK_AUX0 is an arbitrary time domain (e.g. starting at zero), whereas
# CLOCK_REALTIME points to valid UTC time. Both time domains are independent of each other.
#
# Note 1: This test case requires an update-to-date Linux kernel >= 7.2 for clock_gettime(2) and
#         clock_nanosleep(2) support on CLOCK_AUX*.
#
# Note 2: This example does not use CMLDS.
#
# Note 3: This example does not align the Testbench threads with the physical free running clock,
#         which is used for Qbv in i226. One idea would be to apply the required offset adjustments
#         to the TAPRIO schedules.
#

set -e

cd "$(dirname "$0")"

# Interface
INTERFACE=$1
[ -z $INTERFACE ] && INTERFACE="eth0"

# Kill already running daemons
pkill ptp4l || true
pkill phc2sys || true

# Stop ntpd
systemctl stop systemd-timesyncd || true
systemctl stop ntpd || true
systemctl stop chrony || true

# Set NTP time into PHC
phc_ctl ${INTERFACE} set

# Create two vClocks on top of physical PHC
PHC_PHYSICAL=$(ls -1 /sys/class/net/${INTERFACE}/device/ptp)
echo 2 >/sys/class/net/${INTERFACE}/device/ptp/${PHC_PHYSICAL}/n_vclocks

# Create two ptp4l configurations for two domains
cp /etc/gPTP.cfg /etc/gPTP-domain0.cfg
cp /etc/gPTP.cfg /etc/gPTP-domain1.cfg

echo 'domainNumber	0' >>/etc/gPTP-domain0.cfg
echo 'domainNumber	1' >>/etc/gPTP-domain1.cfg

PHCINDEX_VCLOCK1=$(ls -1 /sys/class/net/${INTERFACE}/device/ptp/${PHC_PHYSICAL} | grep ptp | head -n1 | sed -e 's/ptp//g')
PHCINDEX_VCLOCK2=$(ls -1 /sys/class/net/${INTERFACE}/device/ptp/${PHC_PHYSICAL} | grep ptp | tail -n1 | sed -e 's/ptp//g')

# Checkout and build phc2sys capable handling CLOCK_AUX0
if ! [ -d linuxptp ]; then
  git clone https://github.com/richardcochran/linuxptp
  pushd linuxptp
  make -j$(nproc)
  popd
fi

# Start global time ptp4l instance with 802.1AS-2011 endstation profile
phc_ctl /dev/ptp${PHCINDEX_VCLOCK1} set
linuxptp/ptp4l -2 -H -i ${INTERFACE} --phc_index ${PHCINDEX_VCLOCK1} --socket_priority=4 --tx_timestamp_timeout=40 -f /etc/gPTP-domain0.cfg &

# Start working clock ptp4l instance with 802.1AS-2011 endstation profile
phc_ctl /dev/ptp${PHCINDEX_VCLOCK2} set 0
linuxptp/ptp4l -2 -H -i ${INTERFACE} --phc_index ${PHCINDEX_VCLOCK2} --socket_priority=4 --tx_timestamp_timeout=40 -f /etc/gPTP-domain1.cfg &

# Wait for ptp4l instances
sleep 30

# Enable CLOCK_AUX0 in kernel timekeeping first
echo 1 >/sys/kernel/time/aux_clocks/0/aux_clock_enable

# Synchronize CLOCK_REALTIME to global time
linuxptp/phc2sys -s /dev/ptp${PHCINDEX_VCLOCK1} -c CLOCK_REALTIME --step_threshold=1 --transportSpecific=1 -O37 &

# Synchronize CLOCK_AUX0 to working clock
linuxptp/phc2sys -s /dev/ptp${PHCINDEX_VCLOCK2} -c CLOCK_AUX0 --step_threshold=1 --transportSpecific=1 -O0 &

exit 0
