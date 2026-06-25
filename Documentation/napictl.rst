.. SPDX-License-Identifier: BSD-2-Clause
..
.. Copyright (C) 2025-2026 Linutronix GmbH
.. Author Kurt Kanzenbach <kurt@linutronix.de>
..
.. Testbench documentation napictl file.
..

.. _napictl:

NAPI Configuration (napictl)
============================

Introduction
------------

``napictl`` is a small standalone helper that configures the NAPI parameters
``defer-hard-irqs`` and ``gro-flush-timeout`` for an individual queue of a network
interface. It is primarily used to enable kernel side busy polling for the queue that
carries the real time traffic, which reduces the jitter introduced by hardware and software
interrupts. See the :ref:`Busypolling` test for the corresponding use case.

Background
----------

The Linux kernel exposes two NAPI parameters relevant for busy polling:

- ``defer-hard-irqs``: How often the NAPI processing is deferred, i.e. how many times the
  kernel busy polls a queue before re-arming the hardware interrupt.
- ``gro-flush-timeout``: Timeout (in nanoseconds) after which the kernel takes over the NAPI
  processing again. For cyclic real time traffic it has to be larger than the application
  cycle time, otherwise the kernel falls back to interrupt driven processing within a cycle.

Both parameters can be set globally for a whole interface via ``sysfs``::

   /sys/class/net/<interface>/napi_defer_hard_irqs
   /sys/class/net/<interface>/gro_flush_timeout

However, in a converged TSN setup only the queue(s) carrying the real time streams should be
busy polled, while the remaining queues stay interrupt driven to save CPU cycles. The ``sysfs``
interface cannot express this per-queue granularity. ``napictl`` therefore uses the netlink
``netdev`` generic netlink API to resolve the NAPI instance(s) backing a given queue and to set
both parameters only for that queue.

Requirements
------------

``napictl`` is only built when its build and runtime requirements are met:

- ``libnl-3`` and ``libnl-genl-3`` development packages at build time.
- Linux kernel v6.13+ headers providing the ``netdev`` generic netlink commands
  ``NETDEV_CMD_QUEUE_GET`` and ``NETDEV_CMD_NAPI_SET``.
- A network driver that supports per-queue NAPI configuration. This currently works for the
  Intel ``igc`` (i225/i226) and ``igb`` drivers.

If the requirements are not satisfied, ``cmake`` skips the target and prints::

   Building napictl configuration tool requires kernel v6.13+

When the requirements are met, ``cmake`` prints ``Found libnl3: Building napictl configuration
tool`` and the binary is produced as ``build/napictl``. See :ref:`Build` for the package names
on Debian and RHEL based systems.

Command Line Usage
------------------

.. code:: bash

   host: ./napictl -h
   usage: napictl [options]
     options:
       -i, --interface:         Network interface to configure
       -q, --queue:             Queue of network interface to configure
       -d, --defer-hard-irqs:   Set defer-hard-irqs
       -g, --gro-flush-timeout: Set gro-flush-timeout
       -h, --help:              Print this help text
       -v, --verbose:           Print verbose messages
       -V, --version:           Print version

.. list-table:: Options
   :widths: 30 70
   :header-rows: 1

   * - Option
     - Description

   * - ``-i``, ``--interface``
     - Network interface to configure (mandatory).

   * - ``-q``, ``--queue``
     - Queue index to configure. Defaults to ``0``.

   * - ``-d``, ``--defer-hard-irqs``
     - Value for ``defer-hard-irqs``. Defaults to ``0``.

   * - ``-g``, ``--gro-flush-timeout``
     - Value for ``gro-flush-timeout`` in nanoseconds. Defaults to ``0``.

   * - ``-v``, ``--verbose``
     - Print the resolved NAPI ids and the applied settings.

   * - ``-V``, ``--version``
     - Print the version and exit.

   * - ``-h``, ``--help``
     - Print the usage and exit.

.. Note:: ``napictl`` modifies network interface settings and therefore requires
          ``CAP_NET_ADMIN`` (e.g. run it as ``root``).

How It Works
------------

For the requested queue ``napictl``:

1. Resolves the interface index from the interface name.
2. Issues a ``NETDEV_CMD_QUEUE_GET`` dump and matches the queue index to obtain the NAPI ids of
   its receive and transmit NAPI instances.
3. Applies ``defer-hard-irqs`` and ``gro-flush-timeout`` to both the Rx and Tx NAPI instances via
   ``NETDEV_CMD_NAPI_SET``.

Passing ``-v`` prints the resolved NAPI ids and the values that get applied, which is helpful for
debugging the queue to NAPI mapping.

Examples
--------

Configure ``defer-hard-irqs`` and a ``gro-flush-timeout`` of 2 ms (2000000 ns) for queue 0 of
``enp3s0``:

.. code:: bash

   napictl -i enp3s0 -q 0 -d 10 -g 2000000

Reset the parameters for queue 0 back to their defaults (interrupt driven processing):

.. code:: bash

   napictl -i enp3s0 -q 0 -d 0 -g 0

The test scripts wrap ``napictl`` in the ``napi_defer_hard_irqs_queue()`` helper from
``tests/lib/common.sh``, which derives ``gro-flush-timeout`` from the cycle time and applies the
settings per queue:

.. code:: bash

   # napi_defer_hard_irqs_queue($napictl, $interface, $cycle_time_ns, $queue)
   napi_defer_hard_irqs_queue "../../build/napictl" "enp3s0" "1000000" 0

See ``tests/busypolling_napiconf/`` and ``tests/er26/`` for complete examples.
