.. SPDX-License-Identifier: BSD-2-Clause
..
.. Copyright (C) 2022-2026 Linutronix GmbH
.. Author Kurt Kanzenbach <kurt@linutronix.de>
..
.. Testbench documentation build file.
..

Build
=====

The buildsystem is cmake. The applications can be build and installed by:

.. code:: bash

   mkdir build
   cd build
   cmake -DCMAKE_BUILD_TYPE=Release -DWITH_MQTT=TRUE -DRX_TIMESTAMP=TRUE -DTX_TIMESTAMP=TRUE ..
   make -j`nproc`
   sudo make install

Setting the build type is important, as it defines the used compiler
flags. ``Release`` builds the application with optimizations and without debug
symbols. Other build types include: ``Debug`` or ``RelWithDebInfo``.

The applications have the following dependencies:

- Run time: libbpf, libyaml, libxdp, libssl
- Build time: cmake, gcc, clang, llvm, pkg-config
- Utilities: linuxptp, ethtool, iproute2, rt-tests, iperf3

For Debian based systems do:

.. code:: bash

   apt update
   apt install -y build-essential clang llvm cmake pkg-config \
      libbpf-dev libyaml-dev libc6-dev rt-tests ethtool iproute2 \
      iperf3 linuxptp libxdp-dev libssl-dev libmosquitto-dev git bc

For RHEL based systems do:

.. code:: bash

   dnf -y upgrade
   dnf -y install libxdp-devel libyaml-devel clang mosquitto-devel \
            python3-sphinx python3-sphinx_rtd_theme cmake openssl-devel llvm

.. Note:: For RHEL ``libxdp-devel`` is packaged in CodeReadyBuilder repos. More info at
          https://developers.redhat.com/blog/2018/11/15/introducing-codeready-linux-builder. Usually
          a matter of running ``crb enable`` on the subscription-manager registered system with the
          ``EPEL`` repository enabled.

Furthermore, the Linux RealTime Communication ``Testbench`` requires a real-time (PREEMPT_RT) Linux
kernel. A recent LTS version is recommended. Depending on the test case specific networking options
should be set. The following script ``scripts/check_kconfig.pl`` can be used to verify a given Linux
kernel configuration ``.config`` file.

Example: No errors should be printed. Warnings can be evaluated on a case by case basis.

.. code:: bash

   kurt@jax linux % ~/work/RTC-Testbench/scripts/check_kconfig.pl .config
   Checking config file '.config'...

Additional Options
^^^^^^^^^^^^^^^^^^

Some features are added by using additional CMake opitions, the table bellow presents those features
and options.

.. list-table:: Features & CMake options
   :widths: 50 50
   :header-rows: 1

   * - Feature
     - Option

   * - MQTT
     - WITH_MQTT

   * - Show Packet RX Latency
     - RX_TIMESTAMP

   * - Enable TX Hardware Timestamping
     - TX_TIMESTAMP

   * - Compile with AddressSanitizer for debugging
     - WITH_ASAN

   * - Enable/Build Unit tests (requires ``cmocka`` library)
     - WITH_TESTS
