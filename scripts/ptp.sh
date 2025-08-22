#!/bin/bash
#
# Copyright (C) 2021,2025 Linutronix GmbH
# Author Kurt Kanzenbach <kurt@linutronix.de>
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Start ptp and synchronize system to network time.
#

set -e

cd "$(dirname "$0")"

# Interface
INTERFACE=$1
[ -z $INTERFACE ] && INTERFACE="eth0"

# Kill already running daemons
pkill ptp4l || true
pkill phc2sys || true

# Set NTP time into PHC
phc_ctl ${INTERFACE} set

# Stop ntpd
systemctl stop systemd-timesyncd || true
systemctl stop ntpd || true
systemctl stop chrony || true

# Start ptp with 802.1AS-2011 endstation profile
ptp4l -2 -H -i ${INTERFACE} --socket_priority=4 --tx_timestamp_timeout=40 -f /etc/gPTP.cfg &

# Wait for ptp4l
sleep 10

# Configure UTC-TAI offset
pmc -u -b 0 -t 1 "SET GRANDMASTER_SETTINGS_NP clockClass 248 \
        clockAccuracy 0xfe offsetScaledLogVariance 0xffff \
        currentUtcOffset 37 leap61 0 leap59 0 currentUtcOffsetValid 1 \
        ptpTimescale 1 timeTraceable 1 frequencyTraceable 0 \
        timeSource 0xa0"

# Synchronize system to network time
phc2sys -s ${INTERFACE} --step_threshold=1 --transportSpecific=1 -w &

exit 0
