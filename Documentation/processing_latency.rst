.. SPDX-License-Identifier: BSD-2-Clause
..
.. Copyright (C) 2025 Linutronix GmbH
..
.. Processing latency documentation.
..

.. _ProcessingLatency:

Processing Latency
==================

Processing latency metrics quantify how long the Mirror DUT takes to process a full cycle
of packets. It is measured from the hardware RX timestamp of the first packet in the cycle
to the hardware TX timestamp of the response packet(s). These measurements work only in
Mirror mode, with either AF_XDP or AF_PACKET, when both RX and TX hardware timestamping
are enabled.

These metrics allow evaluating Mirror-side timing behavior for both:

- Pure forwarding scenarios (no workload)
- Sense-compute-actuate scenarios (once-per-cycle workload execution)


Timestamp Flow
^^^^^^^^^^^^^^

The following diagram shows where timestamps are captured and what the processing
latency metrics measure:

.. code-block:: text

   RX Path                     Processing                   TX Path
   --------                    ----------                   -------

   [Wire] ──> [NIC] ────> [XDP] ────> [Mirror App] ────> [NIC] ────> [Wire]
                |            |          │       │           │
                |            |           Workload           │
                |       RX SW TS        (optional)          |
                |                       |       |           |
                |                       |       |           |
                RX HW TS         RX App TS    TX SW TS     TX HW TS
                |                                           |
                |                                           |
            [Pkt 1 RX] ◄────────── ProcFirst ──────────► [Pkt 1 TX]
            [Pkt 1 RX] ◄────────── ProcBatch ──────────► [Pkt N TX]

.. note::
   The diagram above shows the AF_XDP case, where the "XDP" stage is a program running on
   the NIC driver's RX path. Over AF_PACKET, there is no XDP program; the same intermediate
   software timestamp (RX SW TS) is instead captured by the kernel's generic RX timestamping
   (``SOF_TIMESTAMPING_RX_SOFTWARE``). The rest of the flow, and all metrics below, are
   identical for both transports.

Timestamp Details
^^^^^^^^^^^^^^^^^

The table below provides precise details for each timestamp capture point:

.. list-table:: Timestamp Capture Points
   :widths: 12 18 20 50
   :header-rows: 1

   * - Timestamp
     - Capture Location
     - When Captured
     - Technical Notes
   * - **RX HW TS**
     - NIC Hardware
     - Packet arrival
     - HW timestamp at NIC
   * - **RX SW TS**
     - XDP hook / kernel RX
     - After DMA completion
     - XDP program, or RX_SOFTWARE flag
   * - **RX App TS**
     - Userspace
     - After XSK polling
     - App extraction timestamp
   * - **TX SW TS**
     - Userspace
     - After TX ring submit
     - Pre-wakeup timestamp
   * - **TX HW TS**
     - NIC Hardware
     - Packet transmission
     - HW timestamp at NIC


**RX HW TS:** Exact hardware capture point varies by NIC (MAC layer, PHY, or DMA descriptor write).

**RX SW TS:** For AF_XDP, taken when the XDP program executes after the NIC DMA completes. For
AF_PACKET, this is the kernel's software RX timestamp (``SOF_TIMESTAMPING_RX_SOFTWARE``),
captured at the ingress of the network stack, before the frame is dispatched to any socket.

**RX App TS:** Timestamp is captured at stat_frame_received(), after userspace dequeues the packet.

**TX SW TS:** Timestamp represents the moment the TX descriptors are submitted to the TX ring.

**TX HW TS:** Exact capture point varies by NIC (MAC egress, PHY, or descriptor completion).

.. note::
   On the RX path, an intermediate software timestamp (RX SW TS) is available for both
   transports: for AF_XDP because all packets are processed by the XDP program before
   they are delivered to userspace, and for AF_PACKET because the kernel timestamps every
   frame at the ingress of the network stack, before it is dispatched to any socket.

   On the TX path there is no equivalent midpoint timestamp for either transport: with
   AF_XDP, packets are transmitted directly from userspace via the TX ring; with AF_PACKET,
   only the userspace submission timestamp (TX SW TS) and the NIC hardware transmit
   timestamp (TX HW TS) are requested, even though the kernel could in principle also
   supply a software TX timestamp (``SOF_TIMESTAMPING_TX_SOFTWARE``). This is a deliberate
   choice to keep both transports' Tx latency model identical.


Processing Latency Metrics
^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following metrics are available in Mirror mode with AF_XDP or AF_PACKET when both RX and TX
hardware timestamping are enabled:


.. list-table:: Primary Processing Latency Metrics
   :widths: 20 30 50
   :header-rows: 1

   * - Metric
     - Calculation
     - Meaning
   * - **ProcFirst**
     - First TX HW TS - First RX HW TS
     - First-packet processing latency
   * - **ProcBatch**
     - Last TX HW TS - First RX HW TS
     - Full-cycle processing latency


**ProcFirst:**
Measures how long the Mirror DUT takes to process the *first* packet of each cycle,
from the first RX hardware timestamp to the first TX hardware timestamp.
This is the primary metric for evaluating the DUT's internal end-to-end processing
responsiveness.

**ProcBatch:**
Measures the total processing time for the entire batch of packets in the cycle,
from the first RX hardware timestamp to the last TX hardware timestamp.
Useful for scenarios with multiple packets per cycle where overall cycle-completion
time matters.

.. note::
   For cycles that contain only one packet, only ``ProcFirst`` is reported.
   ``ProcBatch`` is omitted because it would be identical to ``ProcFirst``.

Configuration
^^^^^^^^^^^^^

Dependencies
------------

Processing latency metrics require both RX and TX hardware timestamp support. Requirements
differ depending on the transport used for the traffic class.

**AF_XDP** (``<Class>XdpEnabled: true``):

.. list-table:: AF_XDP Hardware Timestamp Dependencies
   :widths: 15 20 20
   :header-rows: 1

   * - Component
     - RX Hardware Timestamp
     - TX Hardware Timestamp
   * - **Linux Kernel**
     - >= 6.3
     - >= 6.8
   * - **libbpf**
     - >= 1.2
     - Any version
   * - **libxdp**
     - Any version
     - >= 1.5.2
   * - **NIC Driver Feature**
     - bpf_xdp_metadata_rx_timestamp()
     - XDP_TXMD_FLAGS_TIMESTAMP

.. note::
   The minimum Linux kernel versions listed in the table indicate when the XDP
   timestamping capabilities first became available in the kernel. Real support
   depends on NIC driver implementation.

**AF_PACKET** (``<Class>XdpEnabled: false``):

Needs only a NIC driver supporting ``SIOCSHWTSTAMP`` and ``SO_TIMESTAMPING``; no particular
libbpf/libxdp version is required, since this path uses plain socket APIs instead of AF_XDP
metadata. Check driver support with ``ethtool -T <interface>``.

Build Configuration
-------------------

To enable processing latency metrics, build with both RX and TX timestamp support:

.. code-block:: bash

   cmake -DCMAKE_BUILD_TYPE=Release -DRX_TIMESTAMP=TRUE -DTX_TIMESTAMP=TRUE ..

Enable TX hardware timestamping for your traffic class in the YAML configuration.
For example, to enable it for TsnHigh over AF_XDP:

.. code-block:: yaml

   TsnHighXdpEnabled: true
   TsnHighTxTimeStampEnabled: true

Or over AF_PACKET (no libxdp/libbpf version requirements, see Dependencies above):

.. code-block:: yaml

   TsnHighXdpEnabled: false
   TsnHighTxTimeStampEnabled: true

.. Note:: Hardware timestamping must be supported by the NIC. If unsupported,
          ProcFirst and ProcBatch will not populate. Check ``ethtool -T <interface>``
          to verify hardware timestamping capabilities.

Example Output
^^^^^^^^^^^^^^

Example Mirror-mode log output with processing latency metrics (3 TsnHigh packets
per cycle):

.. code-block:: text

   # Processing Latency Metrics
   TsnHighProcFirstMin=982 [us]
   TsnHighProcFirstMax=1001 [us]
   TsnHighProcFirstAvg=998.476523 [us]
   TsnHighProcFirstOutliers=1

   TsnHighProcBatchMin=983 [us]
   TsnHighProcBatchMax=1003 [us]
   TsnHighProcBatchAvg=1000.237762 [us]
   TsnHighProcBatchOutliers=739

Additional Monitoring Points
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For advanced debugging and system optimization, additional timestamp metrics are
available. These metrics are derived from the timestamp capture points detailed in
the Timestamp Details table above:


.. list-table:: Debugging and Optimization Metrics
   :widths: 18 22 30
   :header-rows: 1

   * - Metric
     - Calculation
     - Meaning
   * - **Rx**
     - RX App TS - RX HW TS
     - Total RX path latency
   * - **RxHw2Sw**
     - RX SW TS - RX HW TS
     - NIC HW to earliest SW timestamp latency
   * - **RxSw2App**
     - RX App TS - RX SW TS
     - Earliest SW timestamp to userspace latency
   * - **Tx**
     - TX HW TS - TX SW TS
     - TX ring to NIC HW latency
   * - **TxHwTimestampMissing**
     - Count
     - Missing or invalid TX HW timestamps


**Rx:**
Measures total receive-path latency from NIC hardware timestamp to the userspace
timestamp captured when the application processes the received frame.
Useful for assessing overall RX path performance.

**RxHw2Sw:**
Measures latency from where the NIC records the hardware timestamp
(MAC / PHY / DMA write depending on NIC implementation) to the earliest available software
timestamp: execution of the XDP program for AF_XDP, or the kernel's
``SOF_TIMESTAMPING_RX_SOFTWARE`` timestamp for AF_PACKET.
Useful for debugging NIC to kernel boundary delays.

**RxSw2App:**
Measures latency between that earliest software timestamp and the application's receive
handler. Includes XSK ring polling and packet extraction for AF_XDP, or ``recvmmsg()``
processing for AF_PACKET.
Useful for debugging kernel to userspace delays.

**Tx:**
Measures latency from software submission to the TX ring to when the NIC hardware
transmits the frame and produces a hardware timestamp.
Useful for analyzing TX ring congestion, DMA delays, or NIC scheduling.

**TxHwTimestampMissing:**
Counts cycles where no valid TX hardware timestamp is available.
Covers cases such as:

- NIC timestamp FIFO overflow
- driver unable to match timestamp
- timestamp not ready before app queries
- invalid timestamp (e.g., TX HW TS ≤ TX SW TS)

Useful for evaluating timestamp reliability and NIC/driver behavior.

.. note::
   These debugging metrics apply to both Mirror and Reference modes.
   (ProcFirst/ProcBatch remain Mirror-only.)

These metrics help drill down into specific bottlenecks when processing latencies
indicate performance issues. Each metric corresponds to a specific segment of the
timestamp flow shown in the diagram above.
