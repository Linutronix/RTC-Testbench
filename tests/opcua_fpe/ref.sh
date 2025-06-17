#!/bin/bash
#
# Copyright (C) 2023 Linutronix GmbH
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
./flow_cml.sh enp3s0
sleep 30

# Start one instance of reference application
cp ../../build/xdp_kern_*.o .
../../build/reference -c reference_opcua_vid200_cml.yaml >ref1.log &

exit 0
