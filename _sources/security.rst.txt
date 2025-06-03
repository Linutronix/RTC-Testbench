.. SPDX-License-Identifier: BSD-2-Clause
..
.. Copyright (C) 2025 Linutronix GmbH
.. Author Kurt Kanzenbach <kurt@linutronix.de>
..
.. Testbench documentation security file.
..

Security
========

Motivation
----------

Driven by legal requirements like EU Cyber Resilience Act (CRA), security for industrial
communication systems is more and more playing a crucial role. The RTC ``Testbench`` can also be
used to measure and optimize the performance of a particular security implementation for
authentication and/or encryption of each processed frame.

The RTC ``Testbench`` demonstrates one exemplary Profinet security implementation. The Profinet
security specification is still under development. This implementation is to be used only for
performance measurements. For instance, what impact does real time frame encryption and decryption
have on quantity structures? Key management, updates, rotation etc. and other mechanisms are not
covered.

Configuration parameters
-------------------------

The parameters which allow to configure frame authentication or encryption are shown below:

.. list-table:: Features & configure options
   :widths: 50 100
   :header-rows: 1

   * - Option
     - Description

   * - SecurityMode (String)
     - One of ``None``, ``AO`` (Authentication only), ``AE`` (Authentication and Encryption)

   * - SecurityAlgorithm (String)
     - One of ``AES256-GCM``, ``AES128-GCM``, ``CHACHA20-POLY1305``

   * - SecurityKey (String|Hex)
     - Key to be used for crypto functions either 16 or 32 bytes depending on selected algorithm

   * - SecurityIvPrefix (String|Hex)
     - Prefix of the IV which is 6 bytes in size

These options are valid for classes TSNHigh, TSNLow, RTC and RTA.

Implementation
--------------

The current implementation uses OpenSSL v3 or later. This means the authentication and encryption
work is performed in software. Therefore, enabling security can have a significant performance
impact.

Future hardware like ASIC(s) or newer generation NIC(s) may provide Profinet security hardware
offloading with the goal of zero performance impact. This is not covered yet.

Example
-------

There are examples for Profinet Authentication only and Authentication and Encryption:

- ``tests/profinet_auth``
- ``tests/profinet_crypt``

For measuring the security performance impact the CPU run times of the involved real time tasks can
be traced. See ``scripts/trace_rtc.bt`` for an example.
