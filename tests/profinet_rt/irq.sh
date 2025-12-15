#!/bin/bash
#
# Copyright (C) 2023 Linutronix GmbH
# Author Kurt Kanzenbach <kurt@linutronix.de>
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Setup IRQ affinities and prios.
#

set -e

source ../lib/common.sh

#
# Command line arguments.
#
INTERFACE=$1
[ -z $INTERFACE ] && INTERFACE="enp3s0" # default: enp3s0

setup_irqs "${INTERFACE}"

exit 0
