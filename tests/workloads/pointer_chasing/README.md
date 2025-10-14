# Pointer Chasing Workload

## Overview

The pointer chasing workload is designed to stress the CPU's memory hierarchy by following a chain
of pointers through memory in a pseudo-random pattern.

### Core Concept

The workload creates a linked list where nodes are distributed randomly throughout a large memory
buffer. When executed, the CPU must follow pointer chains, causing cache misses and memory stalls.
The buffer and span sizes can be customized to target specific hierarchies in the cache subsystem,
or sized sufficiently large for main memory.

### Key Components

1. **Data Structure (`ptr_node`)**

   - 64-byte aligned union containing a pointer to the next node and a value

2. **Setup Phase (`ptr_chase_setup`)**

   - Parses buffer size and span size from command line arguments
   - Allocates memory and creates a randomized linked list
   - Buffer size: Total memory allocated
   - Span size: Used in conjunction with `CACHE_LINE_SIZE` to determine how many linked list nodes
     are traversed

3. **Linked List Generation (`createLinkedList`)**

   - Creates a pseudo-random chain of pointers within the specified span
   - Uses a seeded random number generator for reproducible results
   - Ensures each node is visited exactly once

4. **Execution (`run_ptr_chasing`)**
   - Follows the pointer chain using optimized assembly code
   - Assembly loop continues until reaching a NULL pointer

### Assembly Implementation

The core loop is implemented in assembly for precise control:

```assembly
__chasing_code_loop:
    mov (%rax), %rax    ; Load next pointer
    test %rax, %rax     ; Check if NULL
    jne __chasing_code_loop ; Continue if not NULL
    ret                 ; Return when done
```

### ptr_chase_setup parameters

The `ptr_chase_setup` function expects two arguments:

- **Buffer Size**: Total memory allocated (in hexadecimal)
- **Span Size**: Used in conjunction with `CACHE_LINE_SIZE` to determine how many linked list
  nodes are traversed. As span size approaches buffer size, it will take longer
  to create the LinkedList. Recommended to keep buffer size slightly larger than
  span size.

In the `tests/busypolling_1ms_rtworkload` example, the following values are used:

- Buffer size: 0x4A4000 (~4.6MB total allocation)
- Span size: 0x129000 (~1.2MB used for linked list)

## Example RTC-Testbench configuration file for pointer chasing

See `tests/busypolling_1ms_rtworkload/mirror_vid100_cml.yaml`.

## Build Instructions

From the main project build directory:

```bash
make pointer_chasing                   # Build shared library
```

## Copyright

Copyright (C) 2025 Intel Corporation

## License

BSD-2 Clause and Dual BSD/GPL for all eBPF programs
