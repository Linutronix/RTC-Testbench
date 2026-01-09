#!/bin/bash
#
# Copyright (C) 2024 Linutronix GmbH
# Author Kurt Kanzenbach <kurt@linutronix.de>
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Check coding style.
#

set -e

cd $(dirname $0)

pushd ../..

echo "Checking licenses/copyrights..."
reuse lint

echo "Checking coding style with clang-format ..."
clang-format --Werror --dry-run src/*.c src/*.h
clang-format --Werror --dry-run tests/workloads/*/*.c tests/workloads/*/*.h

echo "Checking naming style with clang-tidy ..."
mkdir build
pushd build
cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ..
make -j$(nproc)
run-clang-tidy
popd
rm -rf build

popd

exit 0
