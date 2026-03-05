#!/bin/bash
#
# Copyright (C) 2026 Linutronix GmbH
# Author Kurt Kanzenbach <kurt@linutronix.de>
#
# SPDX-License-Identifier: BSD-2-Clause
#

set -e

cd "$(dirname "$0")"

# Start PTP
../../../scripts/ptp.sh enp3s0
sleep 30

# Configure flow
./flow_mirror.sh enp3s0
sleep 30

# Start one instance of mirror application
cp ../../../build/xdp_kern_*.o .
../../../build/mirror -c mirror.yaml > /dev/shm/mirror.log &

exit 0
