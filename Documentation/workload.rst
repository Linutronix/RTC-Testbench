.. SPDX-License-Identifier: BSD-2-Clause
..
.. Copyright (C) 2025 Linutronix GmbH
.. Author Kurt Kanzenbach <kurt@linutronix.de>
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

The workload integration guide is documented on Github:

`Workloads <https://github.com/Linutronix/RTC-Testbench/tree/main/tests/workloads>`_

Available Workloads
-------------------

There is one example workload provided: ``pointer_chasing``:

`Pointer Chasing <https://github.com/Linutronix/RTC-Testbench/tree/main/tests/workloads/pointer_chasing>`_
