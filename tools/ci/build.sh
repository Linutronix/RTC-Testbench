#!/bin/bash
#
# Copyright (C) 2024 Linutronix GmbH
# Author Kurt Kanzenbach <kurt@linutronix.de>
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Compile with different options and compilers.
#

set -e

COMPILER="gcc clang"
OPTIONS="WITH_MQTT RX_TIMESTAMP TX_TIMESTAMP"

if [ "$1" == "ubuntu" ]; then
  OPTIONS="WITH_MQTT"
fi

cd $(dirname $0)

pushd ../..

for compiler in $COMPILER; do
  for option in $OPTIONS; do
    mkdir -p build
    pushd build
    echo "Trying 'CC=$compiler cmake -D$option=OFF' ..."
    CC=$compiler cmake -D$option=OFF ..
    make -j$(nproc)
    echo "Trying 'CC=$compiler cmake -D$option=ON' ..."
    CC=$compiler cmake -D$option=ON ..
    make -j$(nproc)
    popd
    rm -rf build
  done
done

make -C Documentation html

popd

exit 0
