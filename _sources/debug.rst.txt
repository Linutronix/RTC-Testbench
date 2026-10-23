.. SPDX-License-Identifier: BSD-2-Clause
..
.. Copyright (C) 2024 Linutronix GmbH
.. Author Kurt Kanzenbach <kurt@linutronix.de>
..
.. Testbench documentation debug file.
..

.. _Debug:

Debug
=====

Debugging of real time outliers
-------------------------------

In case test runs indicate outliers or unusual round-trip times in the statistics, Linux ``ftrace``
can be used to find the root cause. This can be done like this:

.. code:: bash

   # Start tracing
   trace-cmd start -e sched -e syscalls -e irq

   # Set DebugStopTraceOnOutlier to True in reference.yaml or mirror.yaml configuration file

   # Start reference and mirror as usual

   # The reference application stops tracing and terminates after a round-trip time outlier is
   # hit. It writes an information message about it to stderr and to the trace via trace_marker

   # The mirror application stops tracing and terminates after a oneway time outlier is hit. It
   # writes an information message about it to stderr and to the trace via trace_marker

   # Get the trace
   trace-cmd extract -a

   # Copy trace.dat to development machine

   # Analyze trace.dat with kernelshark or tracecompass to find the issue

Furthermore, ``DebugStopTraceOnError`` can be set to ``True`` to stop the tracing as soon as an
error is logged by the applications, e.g., a transmission failure. In contrast to
``DebugStopTraceOnOutlier`` the applications keep running.

.. Note:: Both options require ``tracefs`` to be mounted at ``/sys/kernel/tracing``.
