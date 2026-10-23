.. SPDX-License-Identifier: BSD-2-Clause
..
.. Copyright (C) 2024 Linutronix GmbH
.. Author Kurt Kanzenbach <kurt@linutronix.de>
..
.. Testbench documentation histogram file.
..

.. _Histograms:

Histograms
==========

Motivation
----------

The Linux RealTime Communication Testbench keeps track of the round-trip times of each frame. Currently the minimum,
maximum and average values are displayed in the log files over the whole application run
time. However, it does not show the distribution of the round-trip times. For example, the
distribution is of interest to see the relation of outliers in contrast to regular case.

Therefore, the Linux RealTime Communication Testbench also includes the possibility to generate a histogram file after
a successful run. The histogram itself is a text file which can be easily plotted e.g., with
``gnuplot``.

The histogram functionality is disabled by default. To enable it, apply the following options the
configuration file of the ``reference`` application.

Configuration parameters
-------------------------

The parameters which affect the histogram integration are presented in the table below:

.. list-table:: Features & configure options
   :widths: 50 100
   :header-rows: 1

   * - Option
     - Description

   * - StatsHistogramEnabled
     - Decides whether a histogram is written after successful run or not

   * - StatsHistogramMinimumNS
     - Lower boundary of RTT which is recorded in histogram e.g., 1ms

   * - StatsHistogramMaximumNS
     - Upper boundary of RTT which is recorded in histogram e.g., 10ms

   * - StatsHistogramFile
     - Path to file where to store the histogram after run

Example
-------

The example below shows a histogram of ``tests/profinet``. It is plotted using
``scripts/plot_histogram.pl`` which requires ``gnuplot`` to be installed.

.. image:: images/histogram.png
  :width: 600
  :alt: Histogram of tests/profinet
