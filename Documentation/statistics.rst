.. SPDX-License-Identifier: BSD-2-Clause
..
.. Copyright (C) 2025 Linutronix GmbH
..
.. Testbench documentation statistics file.
..

.. _Statistics:

Statistics
==========

While running the RTC ``Testbench`` it collects statistics about various aspects including round
trip and one way times, errors, processing and workload execution. This sections explains what
statistics are collected and how they can be obtained and visualized.

Statistics
^^^^^^^^^^

The following table shows all gathered statistics. All statistics are collected per traffic class.

.. list-table:: Statistics
   :widths: 50 100
   :header-rows: 1

   * - Name
     - Description

   * - FrameIdErrors
     - Is incremented if a traffic class receives a packet with wrong Profinet frame id. This could
       happen e.g., due to a wrong XDP eBPF program. Should be zero.

   * - FramesReceived
     - How many frames have been received and processed.

   * - FramesSent
     - How many frames have been transmitted.

   * - Oneway[Min,Max,Av] [us]
     - One way time measures the time between sending a packet from reference to mirror (or the
       other way around) and receiving it on the other side. The time stamps for this are taken in
       software on the application level.

   * - OnewayOutliers
     - Incremented if one way time is greater than cycle time. Should be zero.

   * - OutofOrderErrors
     - Is incremented if a frame does not have the expected sequence number. This can indicate out
       of order transmission, but will also be increased if a packet is lost. Should be zero.

   * - PayloadErrors
     - Is incremented if a frame does not have the expected payload. May happen due to driver
       bugs. Should be zero.

   * - ProcBatch[Min,Max,Av] [us]
     - Latency from the first RX hardware timestamp to the last TX hardware timestamp (batch
       processing latency per cycle). See :ref:`Processing Latency <ProcessingLatency>` for detailed information.

   * - ProcFirst[Min,Max,Av] [us]
     - Latency from the first RX hardware timestamp to the first TX hardware timestamp (first-frame
       processing latency per cycle). See :ref:`Processing Latency <ProcessingLatency>` for detailed information.

   * - RoundTrip[Min,Max,Av] [us]
     - Round trip delay measures the time from reference to mirror and back. The delay is calculated
       based on software timestamps. Also the mirror sends back the frame not immediately, but
       rather in next cycle. Therefore, the round trip time should be less than 2 * cycle time.

   * - RoundTripOutliers [us]
     - Is increment if a round trip time is greater than 2 * cycle time. This usually indicates some
       real time issue (e.g., kernel, driver, hardware, ...). Should be zero.

   * - Rx[Min,Max,Av] [us]
     - Latency from NIC hardware to user space based on hardware timestamps.
       See :ref:`Processing Latency <ProcessingLatency>` for detailed information.

   * - RxHw2Xdp[Min,Max,Av] [us]
     - Latency from NIC hardware to XDP program based on hardware timestamps.
       See :ref:`Processing Latency <ProcessingLatency>` for detailed information.

   * - RxWorkload[Min,Max,Av] [us]
     - Duration of workload execution.

   * - RxXdp2App[Min,Max,Av] [us]
     - Latency from XDP program to user space.
       See :ref:`Processing Latency <ProcessingLatency>` for detailed information.

   * - Tx[Min,Max,Av] [us]
     - Latency from user space enqueue to hardware transmit based on hardware timestamps.
       See :ref:`Processing Latency <ProcessingLatency>` for detailed information.

   * - TxHwTimestampMissing
     - Is incremented if hardware timestamp requested, but only software timestamp available.
       See :ref:`Processing Latency <ProcessingLatency>` for detailed information.

.. Note:: Some statistics (e.g., ones based on hardware timestamps) are only available in
          combination with XDP. For detailed information about hardware timestamping, 
          configuration requirements, and troubleshooting, see :ref:`Processing Latency <ProcessingLatency>`.

File log
^^^^^^^^

All statistics are logged once per collection interval into a file log in text form.

MQTT / Grafana
^^^^^^^^^^^^^^

Furthermore, the statistics can be submitted with MQTT and visualized with Grafana.

See :ref:`MQTT` for more information.

JSON/UDP
^^^^^^^^

In addition, there is a JSON/UDP logger. This one submits the statistics in JSON representation per
UDP once per collection interval. This is useful to get the statistics into other tools.

In order to use the JSON/UDP logging, the following configuration parameters can be used:

.. list-table:: JSON/UDP configuration options
   :widths: 50 100
   :header-rows: 1

   * - Option
     - Description

   * - StatsCollectionIntervalNS
     - Interval in which a summary of the data is generated, typically 1s

   * - LogJson
     - Enable and/or disable JSON logging

   * - LogJsonThreadPriority
     - Thread priority for the logging thread, usually low < 7

   * - LogJsonThreadCpu
     - Thread CPU affinity

   * - LogJsonHost
     - IP address/host name where to send the JSON/UDP packets

   * - LogJsonPort
     - Port used by the UDP communication

   * - LogJsonMeasurementName
     - Used to distinguish measurements coming from different machines

The code base contains a script to collect and print the statistics data. The user has to provide
the measurement name and the statistics of interest.

Example:

.. code:: bash

   ./scripts/stat.pl -p 8888 -m testbench1 -t TsnHigh -s FramesSent -s FramesReceived -s Workload*
   Measurement: testbench1 -- TC: TsnHigh
     FramesReceived: 0
     FramesSent: 24016
     RxWorkloadAv: 0
     RxWorkloadMax: 0
     RxWorkloadMin: 18446744073709551615
