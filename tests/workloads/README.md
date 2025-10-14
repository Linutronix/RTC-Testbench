# RTC-Testbench Workload Integration Guide

This document describes the requirements for implementing a workload that can be dynamically loaded into the RTC-Testbench framework.

## Requirements

To be compatible with RTC-Testbench, a workload must:

1. Be compiled as a shared object with position independent code (using the `-fPIC` GCC compiler flag).
2. Implement a runtime function to be called each cycle after completion of the network RX routine.
3. (Optional) Implement a setup function to perform initialization tasks, such as memory allocation, to avoid doing them
   in the time critical path.

## Specifying a workload

The following options are used to configure a TsnHigh RX workload:

| Configuration Option              | Description                                                                                | Type    |
| --------------------------------- | ------------------------------------------------------------------------------------------ | ------- |
| `TsnHighRxWorkloadEnabled`        | Enable/disable workload execution for TSN High traffic class                               | Boolean |
| `TsnHighRxWorkloadFile`           | Path to the shared library containing the workload                                         | String  |
| `TsnHighRxWorkloadSetupFunction`  | Name of the setup function to call during initialization                                   | String  |
| `TsnHighRxWorkloadSetupArguments` | Arguments passed to the setup function (space-separated string)                            | String  |
| `TsnHighRxWorkloadFunction`       | Name of the runtime function called each cycle                                             | String  |
| `TsnHighRxWorkloadArguments`      | Arguments passed to the runtime function                                                   | String  |
| `TsnHighRxWorkloadPrewarm`        | Execute workload immediately when threads spawn (true) or wait for network traffic (false) | Boolean |
| `TsnHighRxWorkloadSkipCount`      | Skip min/max statistics updates for the first N workload iterations                        | Integer |
| `TsnHighRxWorkloadThreadCpu`      | CPU core number to pin the workload thread to                                              | Integer |
| `TsnHighRxWorkloadThreadPriority` | Real-time thread priority (1-99, higher values = higher priority)                          | Integer |

## Examples

The `pointer_chasing` example workload has been provided and can be found in `tests/workloads/pointer_chasing`. A test that uses
the pointer_chasing workload can be found in `tests/busypolling_1ms_rtworkload`.

## Copyright

Copyright (C) 2025 Intel Corporation

## License

BSD-2 Clause and Dual BSD/GPL for all eBPF programs
