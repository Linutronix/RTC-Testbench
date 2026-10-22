.. SPDX-License-Identifier: BSD-2-Clause
..
.. Copyright (C) 2025-2026 Linutronix GmbH
.. Copyright (C) 2025 Intel Corporation
..
.. Testbench documentation workload file.
..

.. _Workload:

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
4. (Optional) Implement a teardown function to release the resources allocated by the setup
   function.

The functions are resolved by name via ``dlsym()`` and have to use the following signatures (see
``src/workload.h``):

.. code:: c

   struct workload_instance {
           int id;     /* Which workload instance is it? */
           int cpu;    /* On which CPU does this instance run on? */
           void *priv; /* Pointer to private data. */
   };

   int setup(struct workload_instance *instance, int argc, char **argv);
   int run(struct workload_instance *instance, int argc, char **argv);
   void teardown(struct workload_instance *instance);

One workload instance is created per configured workload CPU. The setup function is called once
per instance and may store private data in ``instance->priv``. The argument strings configured via
``<Class>RxWorkloadSetupArguments`` and ``<Class>RxWorkloadArguments`` are split at spaces and
passed like command line arguments: ``argv[0]`` is always ``Workload`` and the configured
arguments start at ``argv[1]``.

Specifying a workload
^^^^^^^^^^^^^^^^^^^^^

The following options are used to configure a RX workload:

.. list-table:: Traffic class configuration options
   :widths: 50 100
   :header-rows: 1

   * - Option
     - Description

   * - <Class>RxWorkloadEnabled (Boolean)
     - Enable/disable workload execution for traffic class

   * - <Class>RxWorkloadFile (String)
     - Path to the shared library containing the workload

   * - <Class>RxWorkloadSetupFunction (String)
     - Name of the setup function to call during initialization

   * - <Class>RxWorkloadSetupArguments (String)
     - Arguments passed to the setup function (space-separated string)

   * - <Class>RxWorkloadTeardownFunction (String)
     - Name of the teardown function to call during close

   * - <Class>RxWorkloadFunction (String)
     - Name of the runtime function called each cycle

   * - <Class>RxWorkloadArguments (String)
     - Arguments passed to the runtime function

   * - <Class>RxWorkloadPrewarm (Boolean)
     - Execute workload immediately when threads spawn (true) or wait for network traffic (false)

   * - <Class>RxWorkloadSkipCount (Integer)
     - Skip min/max statistics and outlier updates for the first N workload iterations

   * - <Class>RxWorkloadThreadCpu (CPU list)
     - Comma or space separated list of CPU core numbers to pin the workload threads to. One
       workload thread is created per CPU (maximum 32).

   * - <Class>RxWorkloadThreadPriority (Integer)
     - Real-time thread priority (1-99, higher values = higher priority). Default is 80.

The RX workload feature is implemented for ``TsnHigh``, ``Rtc`` and ``GenericL2`` traffic classes.

Each cycle the Rx thread signals all workload threads after it has received frames (or always, if
``RxWorkloadPrewarm`` is enabled). The workload has to finish before the Tx thread of the traffic
class runs, i.e., between ``ApplicationRxBaseOffsetNS`` and ``ApplicationTxBaseOffsetNS``. If a
workload thread is still running at that point in time, the ``RxWorkloadOutliers`` statistic is
incremented. With ``ApplicationRxTriggeredTx`` (``mirror`` only) the Tx thread waits for the
workload to finish instead, but at most half a cycle. The execution times are reported as
``RxWorkload*`` for a single workload CPU and per workload thread as ``RxWorkload<N>*`` for multiple
workload CPUs. See :ref:`Statistics`.

Pointer Chasing Workload
------------------------

Overview
^^^^^^^^

The pointer chasing workload is designed to stress the CPU's memory hierarchy by following a chain
of pointers through memory in a pseudo-random pattern.

Core Concept
^^^^^^^^^^^^

The workload creates a linked list where nodes are distributed randomly throughout a large memory
buffer. When executed, the CPU must follow pointer chains, causing cache misses and memory stalls.
The buffer and span sizes can be customized to target specific hierarchies in the cache subsystem,
or sized sufficiently large for main memory.

Key Components
^^^^^^^^^^^^^^

1. **Data Structure (ptr_node)**

   - 64-byte aligned union containing a pointer to the next node and a value

2. **Setup Phase (ptr_chase_setup)**

   - Parses buffer size and span size from command line arguments
   - Allocates memory and creates a randomized linked list
   - Buffer size: Total memory allocated
   - Span size: Used in conjunction with ``CACHE_LINE_SIZE`` to determine how many linked list nodes
     are traversed

3. **Linked List Generation (create_linked_list)**

   - Creates a pseudo-random chain of pointers within the specified span
   - Uses a seeded random number generator for reproducible results
   - Ensures each node is visited exactly once

4. **Execution (run_ptr_chasing)**
   - Follows the pointer chain using optimized assembly code
   - Assembly loop continues until reaching a NULL pointer

Assembly Implementation
^^^^^^^^^^^^^^^^^^^^^^^

The core loop is implemented in assembly for precise control:

.. code:: NASM

   __chasing_code_loop:
       mov (%rax), %rax        ; Load next pointer
       test %rax, %rax         ; Check if NULL
       jne __chasing_code_loop ; Continue if not NULL
       ret                     ; Return when done

ptr_chase_setup parameters
^^^^^^^^^^^^^^^^^^^^^^^^^^

The ``ptr_chase_setup`` function expects two arguments:

- **Buffer Size**: Total memory allocated (in hexadecimal)
- **Span Size**: Used in conjunction with ``CACHE_LINE_SIZE`` to determine how many linked list
  nodes are traversed. As span size approaches buffer size, it will take longer to create the
  LinkedList. Recommended to keep buffer size slightly larger than span size.

In the ``tests/busypolling_1ms_rtworkload`` example, the following values are used:

- Buffer size: 0x4A4000 (~4.6MB total allocation)
- Span size: 0x129000 (~1.2MB used for linked list)

Example RTC-Testbench configuration file for pointer chasing
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

See ``tests/busypolling_1ms_rtworkload/mirror.yaml``.

Jacobi 2D Workload
------------------

The ``jacobi_2d`` workload performs a configurable number of iterations of a 2D Jacobi stencil
computation on a small grid (100 x 100 doubles, ~78 KiB). It is a compute bound workload, which
mostly operates within the CPU caches. The execution time scales with the number of iterations.

- Setup function: ``jacobi_2d_setup``, expects one argument: the number of iterations
- Run time function: ``jacobi_2d_run``
- Teardown function: ``jacobi_2d_teardown``

Example configuration snippet:

.. code:: yaml

   RtcRxWorkloadEnabled: true
   RtcRxWorkloadFile: ../workloads/jacobi_2d/jacobi_2d.so
   RtcRxWorkloadSetupFunction: jacobi_2d_setup
   RtcRxWorkloadSetupArguments: "10"
   RtcRxWorkloadFunction: jacobi_2d_run
   RtcRxWorkloadTeardownFunction: jacobi_2d_teardown
   RtcRxWorkloadThreadCpu: 2
   RtcRxWorkloadThreadPriority: 80

Build Instructions
------------------

All workloads located in subdirectories of ``tests/workloads/`` are built automatically as part of
the regular build. Each workload is compiled into a shared library which is placed next to its
sources, e.g., ``tests/workloads/pointer_chasing/pointer_chasing.so``. A single workload can be
built from the main project build directory by its name:

.. code:: bash

   make pointer_chasing                   # Build shared library
   make jacobi_2d                         # Build shared library

New workloads can be added by creating a new subdirectory in ``tests/workloads/`` containing the C
sources.
