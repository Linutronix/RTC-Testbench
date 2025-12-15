#!/bin/bash
#
# Copyright (C) 2022 Linutronix GmbH
# Author Kurt Kanzenbach <kurt@linutronix.de>
#
# SPDX-License-Identifier: BSD-2-Clause
#

set -e

cd "$(dirname "$0")"

# Start PTP
../../../../scripts/ptp.sh enp0s29f2
sleep 10

# Configure flow
./flow.sh enp0s29f2
sleep 10

# Start four instances of mirror applications
cp ../../../../build/xdp_kern_*.o .
../../../../build/mirror -c mirror_vid100.yaml >mirror1.log &
sleep 1
../../../../build/mirror -c mirror_opcua_vid200.yaml >mirror2.log &
sleep 1
../../../../build/mirror -c mirror_opcua_vid300.yaml >mirror3.log &
sleep 1
../../../../build/mirror -c mirror_avtp_vid400.yaml >mirror4.log &

exit 0
