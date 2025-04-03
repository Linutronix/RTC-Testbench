.. SPDX-License-Identifier: BSD-2-Clause
..
.. Copyright (C) 2022-2025 Linutronix GmbH
.. Author Kurt Kanzenbach <kurt@linutronix.de>
..
.. Testbench documentation usage file.
..

Usage
=====

Command Line Usage
^^^^^^^^^^^^^^^^^^

The command line arguments for ``reference`` and ``mirror`` are rather simple. The
PROFINET configuration options are described via external YAML file(s). For a
detailed explanation of these configuration options, see section
:ref:`Configuration`.

Usage for ``reference`` application:

.. code:: bash

   host: ./reference -h
   usage: reference [options]
     options:
       -h, --help:    Print this help text
       -V, --version: Print version
       -c, --config:  Path to config file


Usage for ``mirror`` application:

.. code:: bash

   host: ./mirror -h
   usage: mirror [options]
     options:
       -h, --help:    Print this help text
       -V, --version: Print version
       -c, --config:  Path to config file

Signal Handling
^^^^^^^^^^^^^^^

The ``reference`` and ``mirror`` programs handle the following signals:

.. list-table:: Signal handling
   :widths: 50 100
   :header-rows: 1

   * - Signal
     - Description

   * - SIGINT/SIGTERM
     - Application shutdown. All threads and communucation will be stopped. Can take some time.

   * - SIGUSR1
     - Reset global statistics (e.g. log file). Useful only for testing.

Non-root User
^^^^^^^^^^^^^

The ``reference`` and ``mirror`` programs are real time applications, which
require to have permissions to use real time scheduling priorities, to create
and use RAW and XDP sockets and to perform memory locking. In order to run the
Linux RealTime Communication ``Testbench`` as regular user instead of ``root`` the following Linux
capabilities have to be configured:

- CAP_IPC_LOCK: Memory locking
- CAP_SYS_NICE: Allow to use real time scheduling priorities
- CAP_BPF: Allow to attach BPF programs
- CAP_NET_ADMIN: Allow to use XDP
- CAP_NET_RAW: Allow to create PACKET sockets
- Optional CAP_SYS_ADMIN: Allow to use the xdp-dispatcher from libxdp

Example to set the required capabilities:

.. code:: bash

   $ setcap CAP_IPC_LOCK,CAP_BPF,CAP_SYS_NICE,CAP_NET_RAW,CAP_NET_ADMIN,CAP_SYS_ADMIN+ep reference
   $ getcap reference
   reference cap_net_admin,cap_net_raw,cap_ipc_lock,cap_sys_admin,cap_sys_nice,cap_bpf=ep

In addition, all the provided sample configurations and tests store the log
files in ``/var/log`` directory. Make sure that the user has permissions to
store the log file in that directory or use another location.

Furthermore, the user needs the permissions to access ``/sys/fs/bpf``
file system, which is required by the xdp-dispatcher from libxdp.
