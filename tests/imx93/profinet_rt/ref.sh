#!/bin/bash
#
# Copyright (C) 2024 Linutronix GmbH
# Author Kurt Kanzenbach <kurt@linutronix.de>
#
# SPDX-License-Identifier: BSD-2-Clause
#

set -e

cd "$(dirname "$0")"

# Start PTP
../../../scripts/ptp.sh eth1
sleep 30

# Configure flow
./flow.sh eth1
sleep 30

# Start one instance of reference application
cp ../../../build/xdp_kern_*.o .
../../../build/reference -c reference_vid100.yaml > ref1.log &

exit 0
