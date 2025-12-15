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
../../scripts/ptp.sh enp3s0
sleep 30

# Configure flow
./flow.sh enp3s0
sleep 30

# Start four instances of mirror applications
cp ../../build/xdp_kern_*.o .
../../build/mirror -c mirror.yaml >mirror.log &

exit 0
