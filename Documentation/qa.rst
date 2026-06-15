.. SPDX-License-Identifier: BSD-2-Clause
..
.. Copyright (C) 2022-2026 Linutronix GmbH
.. Author Kurt Kanzenbach <kurt@linutronix.de>
..
.. Testbench documentation qa file.
..

Quality Assurance
=================

License Checks
--------------

The license for the Linux RealTime Communication ``Testbench`` is the permissive BSD-2-Clause. All
files have a valid SPDX identifier (see https://spdx.dev/). The provided license
information can be automatically checked for errors by using the ``reuse``
tool. Example:

.. code:: bash

   % reuse lint

   # SUMMARY

   * Bad licenses:
   * Deprecated licenses:
   * Licenses without file extension:
   * Missing licenses:
   * Unused licenses:
   * Used licenses: BSD-2-Clause, GPL-2.0-only, GPL-2.0-or-later
   * Read errors: 0
   * Files with copyright information: 219 / 219
   * Files with license information: 219 / 219

   Congratulations! Your project is compliant with version 3.0 of the REUSE Specification :-)

No errors should be printed.

Coding Style Check
------------------

The coding style for the Linux RealTime Communication ``Testbench`` is the Linux kernel style. The
rules are described here:

- https://www.kernel.org/doc/html/latest/process/coding-style.html#codingstyle

The coding style can be enforced automatically by using ``clang-format`` (see
https://clang.llvm.org/docs/ClangFormat.html). Example:

.. code:: bash

   % clang-format -i src/*.c src/*.h

This corrects errors in place for all C source files.

Furthermore, the naming of variables, structs and function can be checked (and
fixed inplace) by running ``clang-tidy``:

.. code:: bash

   % mkdir build
   % cd build
   % cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON ..
   % make -j`nproc`
   % run-clang-tidy

Unit Tests
----------

Some code parts like the ring buffer have dedicated unit tests. These tests require ``cmocka``
library. The tests can be invoked like this:

.. code:: bash

   % mkdir build
   % cd build
   % cmake -DWITH_TESTS=ON ..
   % make -j`nproc`
   % make test
