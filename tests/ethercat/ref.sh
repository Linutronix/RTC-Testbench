#!/bin/bash
#
# Copyright (C) 2026 acontis technologies GmbH
# Author Haithem Jebali <h.jebali@acontis.com>
#
# SPDX-License-Identifier: BSD-2-Clause
#

set -e

cd "$(dirname "$0")"

# Start one instance of reference application
cp ../../build/xdp_kern_*.o .
../../build/reference -c reference.yaml >ref.log &

exit 0
