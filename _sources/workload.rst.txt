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

The following options are used to configure a RX workload:

.. list-table:: Traffic class configuration options
   :widths: 50 100
   :header-rows: 1

   * - Option
     - Description

   * - <Class>RxWorkloadEnabled (Boolean)
     - Enable/disable workload execution for TSN High traffic class

   * - <Class>RxWorkloadFile (String)
     - Path to the shared library containing the workload

   * - <Class>RxWorkloadSetupFunction (String)
     - Name of the setup function to call during initialization

   * - <Class>RxWorkloadSetupArguments (String)
     - Arguments passed to the setup function (space-separated string)

   * - <Class>RxWorkloadFunction (String)
     - Name of the runtime function called each cycle

   * - <Class>RxWorkloadArguments (String)
     - Arguments passed to the runtime function

   * - <Class>RxWorkloadPrewarm (Boolean)
     - Execute workload immediately when threads spawn (true) or wait for network traffic (false)

   * - <Class>RxWorkloadSkipCount (Integer)
     - Skip min/max statistics updates for the first N workload iterations

   * - <Class>RxWorkloadThreadCpu (Integer)
     - CPU core number to pin the workload thread to

   * - <Class>RxWorkloadThreadPriority (Integer)
     - Real-time thread priority (1-99, higher values = higher priority)

The RX workload feature is implemented for ``TsnHigh``, ``Rtc`` and ``GenericL2`` traffic classes.

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

Build Instructions
^^^^^^^^^^^^^^^^^^

From the main project build directory:

.. code:: bash

   make pointer_chasing                   # Build shared library
