.. SPDX-License-Identifier: BSD-2-Clause
..
.. Copyright (C) 2025 Linutronix GmbH
.. Copyright (C) 2025 Intel Corporation
..
.. Testbench documentation workload file.
..

Real Time Compute Workloads
===========================

Introduction
------------

The RTC-Testbench simulates a PLC by periodically sending and receiving Ethernet frames. The
workload integration allows to execute a compute workload on the host during the available time
between Rx and Tx. This allows to simulate the compute part in addition to the networking.

Workload Integration
--------------------

This section describes the requirements for implementing a workload that can be dynamically loaded
into the RTC-Testbench framework.

Requirements
^^^^^^^^^^^^

To be compatible with RTC-Testbench, a workload must:

1. Be compiled as a shared object with position independent code (using the ``-fPIC`` GCC compiler
   flag).
2. Implement a runtime function to be called each cycle after completion of the network RX routine.
3. (Optional) Implement a setup function to perform initialization tasks, such as memory allocation,
   to avoid doing them in the time critical path.

Specifying a workload
^^^^^^^^^^^^^^^^^^^^^

The following options are used to configure a TsnHigh RX workload:

.. list-table:: TsnHigh configuration options
   :widths: 50 100
   :header-rows: 1

   * - Option
     - Description

   * - TsnHighRxWorkloadEnabled (Boolean)
     - Enable/disable workload execution for TSN High traffic class

   * - TsnHighRxWorkloadFile (String)
     - Path to the shared library containing the workload

   * - TsnHighRxWorkloadSetupFunction (String)
     - Name of the setup function to call during initialization

   * - TsnHighRxWorkloadSetupArguments (String)
     - Arguments passed to the setup function (space-separated string)

   * - TsnHighRxWorkloadFunction (String)
     - Name of the runtime function called each cycle

   * - TsnHighRxWorkloadArguments (String)
     - Arguments passed to the runtime function

   * - TsnHighRxWorkloadPrewarm (Boolean)
     - Execute workload immediately when threads spawn (true) or wait for network traffic (false)

   * - TsnHighRxWorkloadSkipCount (Integer)
     - Skip min/max statistics updates for the first N workload iterations

   * - TsnHighRxWorkloadThreadCpu (Integer)
     - CPU core number to pin the workload thread to

   * - TsnHighRxWorkloadThreadPriority (Integer)
     - Real-time thread priority (1-99, higher values = higher priority)

Examples
^^^^^^^^

The ``pointer_chasing`` example workload has been provided and can be found in
``tests/workloads/pointer_chasing``. A test that uses the pointer_chasing workload can be found in
``tests/busypolling_1ms_rtworkload``.
