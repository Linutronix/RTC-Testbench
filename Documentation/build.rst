.. SPDX-License-Identifier: BSD-2-Clause
..
.. Copyright (C) 2022-2026 Linutronix GmbH
.. Author Kurt Kanzenbach <kurt@linutronix.de>
..
.. Testbench documentation build file.
..

.. _Build:

Build
=====

The buildsystem is cmake. The applications can be built and installed by:

.. code:: bash

   mkdir build
   cd build
   cmake -DCMAKE_BUILD_TYPE=Release -DWITH_MQTT=TRUE -DRX_TIMESTAMP=TRUE -DTX_TIMESTAMP=TRUE ..
   make -j`nproc`
   sudo make install

Setting the build type is important, as it defines the used compiler
flags. ``Release`` builds the application with optimizations and without debug
symbols. Other build types include: ``Debug`` or ``RelWithDebInfo``.

The build produces the ``reference`` and ``mirror`` applications, the XDP eBPF programs
(``xdp_kern_*.o``) and the example workloads (``tests/workloads/<name>/<name>.so``, see
:ref:`Workload`). If its requirements are met, the ``napictl`` helper is built as well (see
:ref:`napictl`).

``make install`` installs the applications to ``<prefix>/bin``, the XDP eBPF programs to
``<prefix>/<libdir>/rtc-testbench/ebpf`` and the test scenarios to
``<prefix>/share/rtc-testbench/tests``. The applications look up the configured XDP program in
the current working directory first and fall back to the installed eBPF directory. ``napictl``
is not installed and can be used from the build directory.

The applications have the following dependencies:

- Run time: libbpf, libyaml, libxdp, libssl (OpenSSL >= 3.0)
- Build time: cmake, gcc, clang, llvm, pkg-config
- Optional: libmosquitto (MQTT), libnl-3 and libnl-genl-3 (``napictl``), cmocka (unit tests)
- Utilities: linuxptp, ethtool, iproute2, rt-tests, iperf3, bc

For Debian based systems do:

.. code:: bash

   apt update
   apt install -y build-essential clang llvm cmake pkg-config \
      libbpf-dev libyaml-dev libc6-dev rt-tests ethtool iproute2 \
      iperf3 linuxptp libxdp-dev libssl-dev libmosquitto-dev git bc \
      libnl-3-dev libnl-genl-3-dev libcmocka-dev

For RHEL based systems do:

.. code:: bash

   dnf -y upgrade
   dnf -y install gcc clang llvm cmake pkgconf-pkg-config libbpf-devel libxdp-devel \
            libyaml-devel openssl-devel mosquitto-devel libnl3-devel libcmocka-devel \
            python3-sphinx python3-sphinx_rtd_theme

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

Some features are added by using additional CMake options, the table below presents those features
and options.

.. list-table:: Features & CMake options
   :widths: 50 50
   :header-rows: 1

   * - Feature
     - Option

   * - MQTT
     - WITH_MQTT

   * - Rx Hardware Timestamping for latency statistics (requires libbpf >= 1.2)
     - RX_TIMESTAMP

   * - Tx Hardware Timestamping for latency statistics (requires libxdp >= 1.5.2 and Linux kernel
       headers providing ``XDP_TXMD_FLAGS_TIMESTAMP``, i.e., >= v6.8)
     - TX_TIMESTAMP

   * - Compile with AddressSanitizer for debugging
     - WITH_ASAN

   * - Enable/Build Unit tests (requires ``cmocka`` library)
     - WITH_TESTS
