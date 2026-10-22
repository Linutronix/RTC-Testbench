.. SPDX-License-Identifier: BSD-2-Clause
..
.. Copyright (C) 2022-2026 Linutronix GmbH
.. Author Kurt Kanzenbach <kurt@linutronix.de>
..
.. Testbench documentation configuration file.
..

.. _Configuration:

Configuration
=============

Traffic configuration
^^^^^^^^^^^^^^^^^^^^^

The applications itself are configurable. The configuration defines all required parameters such as
how many frames are transmitted per cycle, which traffic classes are active, the cycle time, clock
and many more.

The configuration is based on YAML files and parsed at startup. Valid configurations have to be
created before starting the simulation. Options which are not specified in the YAML file keep
their built-in default values. Unknown options are rejected.

All options with the suffix ``NS`` are time values in nanoseconds. Alternatively, the units ``s``,
``ms`` and ``us`` can be appended to the value, e.g., ``ApplicationBaseCycleTimeNS: 1ms``.

Possible parameters include:

.. list-table:: Configuration options
   :widths: 50 100
   :header-rows: 1

   * - Option
     - Description

   * - ApplicationClockId (String)
     - ``CLOCK_TAI`` or ``CLOCK_MONOTONIC`` or ``CLOCK_REALTIME`` or ``CLOCK_AUX[0-7]``. Default
       is ``CLOCK_TAI``. Rx and Tx hardware timestamping require ``CLOCK_TAI``.

   * - ApplicationBaseStartTimeNS (Integer)
     - Absolute start time of simulation based on ``ApplicationClockId``. If not specified, the
       default is the current time rounded down to full seconds plus 30s. If set to ``0``, the
       threads start immediately without a common base time.

   * - ApplicationBaseStartOffsetNS (Integer)
     - Optional offset added to ``ApplicationBaseStartTimeNS``. Useful for shifting the schedule of
       multiple instances (e.g., several middlewares) running on the same base time. Default is
       ``0``.

   * - ApplicationBaseCycleTimeNS (Integer)
     - Application cycle time. Default is ``1ms``.

   * - ApplicationTxBaseOffsetNS (Integer)
     - Execution offset of Tx threads within Application cycle time

   * - ApplicationRxBaseOffsetNS (Integer)
     - Execution offset of Rx threads within Application cycle time

   * - ApplicationRxWindowNS (Integer)
     - Optional receive window for AF_XDP and AF_PACKET, starting at ``ApplicationRxBaseOffsetNS``.
       The Rx thread repeatedly checks for packets until it collects the configured number of frames
       for the cycle or the window expires. Use this option when packets may arrive shortly after
       the scheduled Rx check, including later frames in a batch, to avoid processing them in the
       next cycle. This can allow a lower ``ApplicationRxBaseOffsetNS``: the Rx thread starts
       checking earlier and continues checking for frames throughout the receive window. Set it to
       ``0`` to make a single receive attempt (the default). ``ApplicationRxBaseOffsetNS`` plus the
       window must not exceed ``ApplicationBaseCycleTimeNS`` and, unless
       ``ApplicationRxTriggeredTx`` is enabled, must not exceed ``ApplicationTxBaseOffsetNS``, so
       that Rx polling cannot overlap Tx. Polling for missing frames consumes CPU throughout the
       window and can delay other real-time work. Burst traffic classes (RTA, DCP, LLDP, UDP) ignore
       the window and always make a single receive attempt, because they only receive frames once
       per burst period.

   * - ApplicationRxTriggeredTx (Boolean)
     - Mirror only: trigger Tx threads after Rx threads and any enabled Rx workload finish.
       When enabled, ``ApplicationTxBaseOffsetNS`` does not schedule Tx threads. Not supported
       in combination with UDP traffic classes.

   * - ApplicationXdpProgram (String)
     - Application specific XDP program (eBPF object file), e.g., ``xdp_kern_profinet_vid100.o``.
       The file is first looked up relative to the current working directory and then in the
       installation directory ``<prefix>/<libdir>/rtc-testbench/ebpf``.

   * - <Class>Enabled (Boolean)
     - Selects whether this traffic is active or not. A traffic class is only active, if it is
       enabled and ``<Class>NumFramesPerCycle`` is greater than zero. Default is ``false``.

   * - <Class>SocketType (String)
     - ``AF_PACKET`` or ``AF_XDP`` (only valid for XDP traffic classes) or ``DPDK`` (Not supported
       currently). Default is ``AF_XDP`` for TsnHigh, TsnLow, Rtc and Rta and ``AF_PACKET`` for
       all others.

   * - <Class>XdpSkbMode (Boolean)
     - Use XDP skb mode (for testing XDP code or driver implementation). Only XDP traffic classes.

   * - <Class>XdpZcMode (Boolean)
     - Use XDP zero copy mode. Only XDP traffic classes.

   * - <Class>XdpWakeupMode (Boolean)
     - Use XDP wakeup mode. Only XDP traffic classes.

   * - <Class>XdpBusyPollMode (Boolean)
     - Drive XDP socket in busy poll mode. Only XDP traffic classes.

   * - <Class>TxTimeEnabled (Boolean)
     - Use Tx Launch Time for all transmitted frames (requires ETF Qdisc). Only valid for TsnHigh,
       TsnLow and GenericL2. In combination with ``AF_XDP`` it requires libxdp >= v1.5.0 and Linux
       kernel >= v6.15 at build time.

   * - <Class>TxTimeOffsetNS (Integer)
     - Optional Tx Launch Time offset relative to Qbv schedule and cycle time. Only valid for
       TsnHigh, TsnLow and GenericL2.

   * - <Class>TxTimeStampEnabled (Boolean)
     - Enable TX hardware timestamping for latency measurement (requires TX_TIMESTAMP build option
       and ``ApplicationClockId: CLOCK_TAI``). Only XDP traffic classes, but works with both
       ``AF_XDP`` and ``AF_PACKET`` sockets. See :ref:`Processing Latency <ProcessingLatency>`.

   * - <Class>IgnoreRxErrors (Boolean)
     - By default, the applications perform consistency checks for all received frames. This option
       disables these checks. Do not enable this. This is only useful for testing e.g., overload
       scenarios.

   * - <Class>Vid (Integer)
     - VLAN ID used for traffic generation

   * - <Class>Pcp (Integer)
     - VLAN PCP used for traffic generation

   * - <Class>NumFramesPerCycle (Integer)
     - Number of frames transmitted per cycle. For the burst traffic classes (Rta, Dcp, Lldp,
       UdpHigh, UdpLow) this is the number of frames transmitted per ``<Class>BurstPeriodNS``.

   * - <Class>BurstPeriodNS (Integer)
     - Period in which ``<Class>NumFramesPerCycle`` frames are generated. Only valid for the burst
       traffic classes Rta, Dcp, Lldp, UdpHigh and UdpLow. Defaults: Rta 200ms, Dcp 2s, Lldp 5s,
       UdpHigh/UdpLow 1s.

   * - <Class>PayloadPattern (String)
     - Payload pattern for frame content. The payload is a sequence of bytes. If the payload pattern
       is smaller than the frame size, zero padding is added.

   * - <Class>FrameLength (Integer)
     - Length of frames excluding four bytes of FCS

   * - <Class>SecurityMode (String)
     - One of ``None``, ``AO`` (Authentication only), ``AE`` (Authentication and Encryption).
       Only valid for TsnHigh, TsnLow, Rtc and Rta. See :ref:`Security`.

   * - <Class>SecurityAlgorithm (String)
     - One of ``AES256-GCM``, ``AES128-GCM``, ``CHACHA20-POLY1305``

   * - <Class>SecurityKey (String)
     - Key to be used for crypto functions. The characters of the string are used as raw key
       bytes. It has to be 16 bytes (``AES128-GCM``) or 32 bytes (``AES256-GCM``,
       ``CHACHA20-POLY1305``) long.

   * - <Class>SecurityIvPrefix (String)
     - Prefix of the IV which is 6 bytes (characters) in size

   * - <Class>RxQueue (Integer)
     - Receive queue

   * - <Class>TxQueue (Integer)
     - Transmit queue. This is not used at the moment. Tx queue is determined via
       ``SocketPriority``. For XDP the socket is bound to ``RxQueue``.

   * - <Class>SocketPriority (Integer)
     - Socket priority. It is used for QoS of the operating system.

   * - <Class>TxThreadPriority (Integer)
     - Tx thread priority based on SCHED_FIFO

   * - <Class>RxThreadPriority (Integer)
     - Rx thread priority based on SCHED_FIFO

   * - <Class>TxThreadCpu (Integer)
     - Tx thread CPU affinity

   * - <Class>RxThreadCpu (Integer)
     - Rx thread CPU affinity

   * - <Class>Interface (String)
     - Network interface to be used

   * - <Class>Destination (MAC/IP Address)
     - Destination MAC address for Layer 2 traffic classes. Destination IP address or host name
       for UdpHigh and UdpLow.

   * - <Class>Source (IP Address)
     - Source IP address. Only valid for UdpHigh and UdpLow.

   * - <Class>Port (String)
     - UDP port. Only valid for UdpHigh and UdpLow.

   * - GenericL2Name (String)
     - Name of the simulated protocol, e.g., ``OpcUa``. It is used as prefix in the log files and
       statistics instead of ``GenericL2``.

   * - GenericL2EtherType (Hex)
     - EtherType used for the GenericL2 traffic class, e.g., ``0xb62c`` for OPC/UA PubSub.

   * - GenericL2ProtocolType (String)
     - ``L2`` (default) for generic Layer 2 frames or ``EtherCAT`` for EtherCAT frames.

   * - <Class>RxWorkload* (various)
     - Real time compute workload executed after the Rx processing. Only valid for TsnHigh, Rtc and
       GenericL2. See :ref:`Workload` for all options.

   * - LogThreadPriority (Integer)
     - Log thread priority based on SCHED_FIFO

   * - LogThreadCpu (Integer)
     - Log thread CPU affinity

   * - LogFile (String)
     - Path to log file

   * - LogLevel (String)
     - Log level, one of ``Debug``, ``Info``, ``Warning``, ``Error``

   * - StatsCollectionIntervalNS (Integer)
     - Interval in which a summary of the data is generated, typically 1s, i.e. 1000000000Ns

   * - StatsHistogramEnabled (Boolean)
     - Decides whether a histogram is written after successful run or not. Only used by
       ``reference``. See :ref:`Histograms`.

   * - StatsHistogramMinimumNS (Integer)
     - Lower boundary of RTT which is recorded in histogram e.g., 1ms

   * - StatsHistogramMaximumNS (Integer)
     - Upper boundary of RTT which is recorded in histogram e.g., 10ms

   * - StatsHistogramFile (String)
     - Path to file where to store the histogram after run

   * - LogMqtt (Boolean)
     - Enable and disable MQTT logging

   * - LogMqttThreadPriority (Integer)
     - Thread priority for the logging thread, usually low < 7

   * - LogMqttThreadCpu (Integer)
     - Thread CPU affinity

   * - LogMqttBrokerIP (IP Address)
     - IP address where MQTT broker is running

   * - LogMqttBrokerPort (Integer)
     - Port used by the MQTT Broker, default value is 1883

   * - LogMqttKeepAliveSecs (Integer)
     - Keep alive time for the connection, default value 60s

   * - LogMqttMeasurementName (String)
     - Used to distinguish measurements coming from different machines.

   * - LogJson (Boolean)
     - Enable and disable JSON logging

   * - LogJsonThreadPriority (Integer)
     - Thread priority for the logging thread, usually low < 7

   * - LogJsonThreadCpu (Integer)
     - Thread CPU affinity

   * - LogJsonHost (IP Address)
     - IP address or host name where JSON/UDP messages should be sent to

   * - LogJsonPort (Integer)
     - Port used for JSON/UDP messages, default value is 58415

   * - LogJsonMeasurementName (String)
     - Used to distinguish measurements coming from different machines

   * - DebugStopTraceOnOutlier (Boolean)
     - Stop Linux kernel tracing and terminate the application if round trip or oneway time
       exceeds expected value. See :ref:`Debug`.

   * - DebugStopTraceOnError (Boolean)
     - Stop Linux kernel tracing if an error is logged (e.g. transmission failure)

   * - DebugMonitorMode (Boolean)
     - Monitor mode for Fraunhofer FPGA measurement. Only supported with ``AF_XDP``.

   * - DebugMonitorDestination (MAC Address)
     - Destination address of first frame per burst

The possible traffic classes are:

- TsnHigh: TSN Stream High traffic
- TsnLow: TSN Stream Low traffic
- Rtc: Real time cyclic traffic
- Rta: Real time acyclic traffic
- Dcp: Discovery and basic Configuration Protocol
- Lldp: Link-Layer Discovery Protocol
- UdpHigh: Connection traffic Best Effort High
- UdpLow: Connection traffic Best Effort Low
- GenericL2: Traffic class to simulate any kind of protocol such as OPC/UA

.. Note:: Not all traffic classes have all options available. Specifying an option for a traffic
          class which does not support it results in an ``Unknown option`` error. The
          following table shows which option groups are valid for which traffic classes:

.. list-table:: Option groups per traffic class
   :widths: 40 60
   :header-rows: 1

   * - Option group
     - Traffic classes

   * - Generic options (Enabled, SocketType, Vid, Pcp, NumFramesPerCycle, PayloadPattern,
       FrameLength, Queues, Priorities, CPUs, Interface, IgnoreRxErrors)
     - All

   * - XDP options (Xdp*, TxTimeStampEnabled) and ``SocketType: AF_XDP``
     - TsnHigh, TsnLow, Rtc, Rta, GenericL2

   * - Tx Launch Time (TxTimeEnabled, TxTimeOffsetNS)
     - TsnHigh, TsnLow, GenericL2

   * - Security (Security*)
     - TsnHigh, TsnLow, Rtc, Rta

   * - Workload (RxWorkload*)
     - TsnHigh, Rtc, GenericL2

   * - BurstPeriodNS
     - Rta, Dcp, Lldp, UdpHigh, UdpLow

   * - Destination (MAC)
     - TsnHigh, TsnLow, Rtc, Rta, Dcp, Lldp, GenericL2

   * - Destination (IP), Source, Port
     - UdpHigh, UdpLow

   * - Name, EtherType, ProtocolType
     - GenericL2

.. Note:: The ``GenericL2`` traffic class cannot be combined with any of the PROFINET traffic
          classes (TsnHigh, TsnLow, Rtc, Rta, Dcp, Lldp, UdpHigh, UdpLow) within one
          instance. For simulating PROFINET and other middlewares in parallel start multiple
          instances of ``reference`` and ``mirror`` with different configurations.

.. Note:: The ``GenericL2`` traffic class is not PROFINET specific, but rather used to simulate general purpose Ethernet
          (Layer 2) based protocols such as OPC/UA PubSub, AVTP or EtherCAT. In addition to the other traffic classes,
          the EtherType is configurable.

.. Note:: The ``XdpBusyPollMode`` option requires Linux kernel >= v6.5. Previous Linux kernel version do not support
          this feature with ``PREEMPT_RT`` enabled.

.. Note:: The **security settings** are only valid for the PROFINET real time traffic
          classes TsnHigh, TsnLow, Rtc and Rta. Furthermore, the Linux RealTime Communication ``Testbench`` demonstrates only one
          exemplary implementation. The PROFINET security specification is still under
          development. This implementation is to be used only for performance measurements. For
          instance, what impact does real time frame encryption and decryption has on quantity
          structures? Key updates and other mechanisms are not covered.

Sample configuration files are provided for Intel i210, i225/i226 and stmmac (e.g., Intel Elkhart
Lake, NXP i.MX93 and ST STM32MP2).

Starting point for PROFINET TSN:

- https://github.com/Linutronix/RTC-Testbench/tree/main/tests/profinet

Starting point for OPC/UA:

- https://github.com/Linutronix/RTC-Testbench/tree/main/tests/opcua

At minimum MAC and IP addresses as well as network interface names have to be adjusted.

Network interface configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The configuration of network interfaces is crucial. Different NICs have
different capabilities such as queue configuration, routing, Qbv, ...  For instance,
the PROFINET specification specifies which traffic class is transmitted and
received on which queue. It also defines which Ethernet frames are VLAN tagged
and which are transmitted untagged. The configuration of all NIC settings are
either performed by ``tc`` from ``iproute2`` package or ``ethtool``. That
depends on the Linux driver implementation.

The reference applications provides sample scripts in ``tests/`` folder.

These scripts configure multiple settings:

- Tx queue assignment
- Rx queue assignment
- Qbv schedule
- IRQ coalescing
- Threaded NAPI mode
- IRQ and NAPI thread priorities

All of these settings are required for the PROFINET simulation to work properly.

UDP communication
^^^^^^^^^^^^^^^^^

The UDP communication relies on standard sockets. It assumes that corresponding VLAN interfaces have
been setup on the system. VLAN interfaces can be created by multiple ways: NetworkManager, Linux
Distribution mechanisms or manually.

Example for manual configuration:

.. code:: bash

   ip link add link eth0 name eth0.100 type vlan id 100
   ip addr add XXX dev eth0.100

Whenever a UDP packet is transmitted or received on a VLAN network interface the kernel will
automatically add or strip the VLAN tag. The PCP value is derived from the socket priority. This
mapping between socket priority and PCP values is configurable.

Example:

.. code:: bash

   ip link set eth0.100 type vlan egress-qos-map 0:0 1:1

The configured socket priorities have to match ``UdpHighSocketPriority`` and
``UdpLowSocketPriority`` in the yaml files.

.. Note:: In case the UDP communication does not work check the VLAN interface configurations. In
          case it is still not working check whether the system uses a firewall which filters UDP
          communication on the configured ports.
