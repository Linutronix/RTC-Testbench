.. SPDX-License-Identifier: BSD-2-Clause
..
.. Copyright (C) 2022-2024 Linutronix GmbH
.. Author Kurt Kanzenbach <kurt@linutronix.de>
..
.. Testbench documentation configuration file.
..

.. _Configuration:

Configuration
=============

Traffic configuration
^^^^^^^^^^^^^^^^^^^^^

The applications itself are configurable. The configuration defines all required
parameters such as how many frames are transmitted per cycle, which traffic
classes are active, the period and clock, ...

The configuration is based on YAML files and parsed at startup. Valid
configurations have to be created before starting the simulation.

Possible parameters include:

- ApplicationClockId (String): ``CLOCK_TAI`` or ``CLOCK_MONOTONIC``
- ApplicationBaseStartTimeNS (Integer): Absolute start time of simulation (or nothing for
  default value now + 30s)
- ApplicationBaseCycleTimeNS (Integer): Application cycle time
- ApplicationTxBaseOffsetNS (Integer): Execution offset of Tx threads within Application cycle time
- ApplicationRxBaseOffsetNS (Integer): Execution offset of Rx threads within Application cycle time
- ApplicationXdpProgram (String): Application specific XDP program
- <Class>Enabled (Boolean): Selects whether this traffic is active or not
- <Class>XdpEnabled (Boolean): Use XDP instead of RAW sockets
- <Class>XdpSkbMode (Boolean): Use XDP skb mode (for testing XDP code or driver implementation)
- <Class>XdpZcMode (Boolean): Use XDP zero copy mode
- <Class>XdpWakeupMode (Boolean): Use XDP wakeup mode
- <Class>XdpBusyPollMode (Boolean): Drive XDP socket in busy poll mode
- <Class>TxTimeEnabled (Boolean): Use Tx Launch Time for all transmitted frames (requires ETF Qdisc and is not
  compatible with XDP)
- <Class>TxTimeOffsetNS (Integer): Optional Tx Launch Time offset relative to Qbv schedule and cycle time
- <Class>IgnoreRxErrors (Boolean): By default, the applications perform consistency checks for all received frames. This
  option disables these checks. Do not enable this. This is only useful for testing e.g., overload scenarios.
- <Class>Vid (Integer): VLAN ID used for traffic generation
- <Class>Pcp (Integer): VLAN PCP used for traffic generation
- <Class>NumFramesPerCycle (Integer): Number of frames transmitted per cycle
- <Class>PayloadPattern (String): Payload pattern for frame content. The payload is
  a sequence of bytes. If the payload pattern is smaller than the frame size, zero
  padding is added.
- <Class>FrameLength (Integer): Length of frames excluding four bytes of FCS
- <Class>SecurityMode (String): One of ``None``, ``AO`` (Authentication only), ``AE`` (Authentication and Encryption)
- <Class>SecurityAlgorithm (String): One of ``AES256-GCM``, ``AES128-GCM``, ``CHACHA20-POLY1305``
- <Class>SecurityKey (String): Key to be used for crypto functions either 16 or 32 bytes depending on selected algorithm
- <Class>SecurityIvPrefix (String): Prefix of the IV which is 6 bytes in size
- <Class>RxQueue (Integer): Receive queue
- <Class>TxQueue (Integer): Transmit queue
- <Class>SocketPriority (Integer): Socket priority
- <Class>TxThreadPriority (Integer): Tx thread priority based on SCHED_FIFO
- <Class>RxThreadPriority (Integer): Rx thread priority based on SCHED_FIFO
- <Class>TxThreadCpu (Integer): Tx thread CPU affinity
- <Class>RxThreadCpu (Integer): Rx thread CPU affinity
- <Class>Interface (String): Network interface to be used
- <Class>Destination (MAC Address): Destination MAC address
- LogThreadPriority (Integer): Log thread priority based on SCHED_FIFO
- LogThreadCpu (Integer): Log thread CPU affinity
- LogFile (String): Path to log file
- LogLevel (String): Log level, one of Debug, Info, Warning, Error
- DebugStopTraceOnOutlier (Integer): Stop Linux kernel tracing if round trip or oneway time exceeds
  expected value
- DebugStopTraceOnError (Boolean): Stop Linux kernel tracing if error happened (e.g. transmission failure)
- DebugMonitorMode (Boolean): Monitor mode for Fraunhofer FPGA measurement
- DebugMonitorDestination (MAC Address): Destination address of first frame per burst

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

.. Note:: Not all traffic class have all options available. For instance, only real time traffic classes such as TSN or
          RT make use of XDP sockets. When the XDP option is enabled the traffic classes utilize ``AF_XDP`` instead of
          ``AF_PACKET`` sockets for Ethernet communication.

.. Note:: The ``GenericL2`` traffic class is not PROFINET specific, but rather used to simulate general purpose Ethernet
          (Layer 2) based protocols such as OPC/UA PubSub. In addition, to the other traffic classes the EtherType is
          configurable.

.. Note:: The ``XdpBusyPollMode`` option requires Linux kernel >= v6.5. Previous Linux kernel version do not support
          this feature with ``PREEMPT_RT`` enabled.

.. Note:: The **security settings** are only valid for the PROFINET real time traffic
          classes. Furthermore, the Linux RealTime Communication ``Testbench`` demonstrates only one
          exemplary implementation. The PROFINET security specification is still under
          development. This implementation is to be used only for performance measurements. For
          instance, what impact does real time frame encryption and decryption has on quantity
          structures? Key updates and other mechanisms are not covered.

Sample configuration files are provided for Intel i225/i226 and stmmac.

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
