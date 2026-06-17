#!/bin/bash
#
# Copyright (C) 2024-2026 Linutronix GmbH
# Author Kurt Kanzenbach <kurt@linutronix.de>
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Compile with different options and compilers.
#

set -e

COMPILER="gcc clang"
OPTIONS="WITH_MQTT RX_TIMESTAMP TX_TIMESTAMP"

cd $(dirname $0)

pushd ../..

combos=("")
for option in $OPTIONS; do
  new_combos=()
  for combo in "${combos[@]}"; do
    new_combos+=("$combo -D$option=OFF")
    new_combos+=("$combo -D$option=ON")
  done
  combos=("${new_combos[@]}")
done

for compiler in $COMPILER; do
  for combo in "${combos[@]}"; do
    mkdir -p build
    pushd build
    echo "Trying 'CC=$compiler cmake$combo' ..."
    CC=$compiler cmake $combo ..
    make -j$(nproc)
    popd
    rm -rf build
  done
done

make -C Documentation html

popd

exit 0
