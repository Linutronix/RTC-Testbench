# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (C) 2020-2025 Linutronix GmbH
# Author Kurt Kanzenbach <kurt@linutronix.de>
#

cmake_minimum_required(VERSION 3.10)
project(rtc-testbench)

set(VERSION "5.3")

include(CheckIncludeFiles)
include(CheckFunctionExists)
include(CheckSymbolExists)
include(GNUInstallDirs)

find_package(PkgConfig REQUIRED)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

pkg_search_module(YAML yaml-0.1 REQUIRED)
pkg_search_module(LIBBPF libbpf REQUIRED)
pkg_search_module(LIBXDP libxdp REQUIRED)
pkg_search_module(LIBCRYPTO libcrypto>=3.0 REQUIRED)

check_symbol_exists(SO_BUSY_POLL "sys/socket.h" HAVE_SO_BUSY_POLL)
check_symbol_exists(SO_PREFER_BUSY_POLL "sys/socket.h" HAVE_SO_PREFER_BUSY_POLL)
check_symbol_exists(SO_BUSY_POLL_BUDGET "sys/socket.h" HAVE_SO_BUSY_POLL_BUDGET)
check_symbol_exists(XDP_TXMD_FLAGS_LAUNCH_TIME "linux/if_xdp.h" HAVE_XDP_FLAGS_TX_TIME)
check_symbol_exists(XDP_TXMD_FLAGS_TIMESTAMP "linux/if_xdp.h" HAVE_XDP_FLAGS_TX_HWTSTAMP)

add_executable(reference
  src/reference.c
  src/config.c
  src/utils.c
  src/log.c
  src/logviamqtt.c
  src/stat.c
  src/ring_buffer.c
  src/thread.c
  src/tsn_thread.c
  src/rtc_thread.c
  src/rta_thread.c
  src/dcp_thread.c
  src/lldp_thread.c
  src/udp_thread.c
  src/layer2_thread.c
  src/net.c
  src/xdp.c
  src/tx_time.c
  src/security.c
  src/packet.c
  src/hist.c
  src/workload.c
  src/print.c)
add_executable(mirror
  src/mirror.c
  src/config.c
  src/utils.c
  src/log.c
  src/logviamqtt.c
  src/stat.c
  src/ring_buffer.c
  src/thread.c
  src/tsn_thread.c
  src/rtc_thread.c
  src/rta_thread.c
  src/dcp_thread.c
  src/lldp_thread.c
  src/udp_thread.c
  src/layer2_thread.c
  src/net.c
  src/xdp.c
  src/tx_time.c
  src/security.c
  src/packet.c
  src/hist.c
  src/workload.c
  src/print.c)

option(WITH_MQTT, "Enable/Disable logging via MQTT" OFF)
if (WITH_MQTT)
  pkg_search_module(MOSQUITTO libmosquitto REQUIRED)
  target_link_libraries(reference ${MOSQUITTO_LIBRARIES})
  target_link_libraries(mirror ${MOSQUITTO_LIBRARIES})
  target_include_directories(reference PUBLIC ${MOSQUITTO_INCLUDE_DIRS})
  target_include_directories(mirror PUBLIC ${MOSQUITTO_INCLUDE_DIRS})
endif()

option(RX_TIMESTAMP "Enable RX timestamp support (requires libbpf >= 1.2)" OFF)
option(TX_TIMESTAMP "Enable TX timestamp support (requires libxdp >= 1.4.1)" OFF)

if(RX_TIMESTAMP)
  pkg_check_modules(LIBBPF_REQUIRED_FOR_RX_TIMESTAMP libbpf>=1.2)
  if(NOT LIBBPF_REQUIRED_FOR_RX_TIMESTAMP_FOUND)
    message(FATAL_ERROR "RX_TIMESTAMP requires libbpf >= 1.2, but version ${LIBBPF_VERSION} was found.")
  endif()
endif()

if(TX_TIMESTAMP)
  if(NOT ((${LIBXDP_VERSION} GREATER_EQUAL 1.4.1) AND (${HAVE_XDP_FLAGS_TX_HWTSTAMP})))
    message(FATAL_ERROR "TX_TIMESTAMP requires libxdp >= 1.4.1 and kernel support for XDP_TXMD_FLAGS_TIMESTAMP")
  endif()
endif()

target_compile_options(reference PRIVATE -Wall -Wshadow -std=gnu99 -Wvla)
target_compile_options(mirror PRIVATE -Wall -Wshadow -std=gnu99 -Wvla)

target_compile_definitions(reference PRIVATE -D_GNU_SOURCE)
target_compile_definitions(mirror PRIVATE -D_GNU_SOURCE)

option(WITH_ASAN, "Build with AddressSanitizer for debugging" OFF)
if (WITH_ASAN)
  target_compile_options(reference PRIVATE -fsanitize=address)
  target_compile_options(mirror PRIVATE -fsanitize=address)

  target_link_options(reference PRIVATE -fsanitize=address)
  target_link_options(mirror PRIVATE -fsanitize=address)
endif()

# Export symbols for dynamically loaded workloads
target_link_options(mirror PRIVATE -Wl,--export-dynamic)

target_link_libraries(reference Threads::Threads)
target_link_libraries(reference ${YAML_LIBRARIES})
target_link_libraries(reference ${LIBBPF_LIBRARIES})
target_link_libraries(reference ${LIBXDP_LIBRARIES})
target_link_libraries(reference ${LIBCRYPTO_LIBRARIES})

target_link_libraries(mirror Threads::Threads)
target_link_libraries(mirror ${YAML_LIBRARIES})
target_link_libraries(mirror ${LIBBPF_LIBRARIES})
target_link_libraries(mirror ${LIBXDP_LIBRARIES})
target_link_libraries(mirror ${LIBCRYPTO_LIBRARIES})

target_include_directories(reference PRIVATE "${PROJECT_BINARY_DIR}")
target_include_directories(reference PRIVATE "src")
target_include_directories(reference PUBLIC ${YAML_INCLUDE_DIRS})
target_include_directories(reference PUBLIC ${LIBBPF_INCLUDE_DIRS})
target_include_directories(reference PUBLIC ${LIBXDP_INCLUDE_DIRS})
target_include_directories(reference PUBLIC ${LIBCRYPTO_INCLUDE_DIRS})
target_include_directories(mirror PRIVATE "${PROJECT_BINARY_DIR}")
target_include_directories(mirror PRIVATE "src")
target_include_directories(mirror PUBLIC ${YAML_INCLUDE_DIRS})
target_include_directories(mirror PUBLIC ${LIBBPF_INCLUDE_DIRS})
target_include_directories(mirror PUBLIC ${LIBXDP_INCLUDE_DIRS})
target_include_directories(mirror PUBLIC ${LIBCRYPTO_INCLUDE_DIRS})

#
# Check for XDP and Tx Launch Time support. It requires: libxdp >= 1.5.0 and Linux v6.15.
#
if ((${LIBXDP_VERSION} GREATER_EQUAL 1.5.0) AND (${HAVE_XDP_FLAGS_TX_TIME}))
  message(STATUS "XDP and Tx Launch Time support available using libxdp version: ${LIBXDP_VERSION}")
  set(HAVE_XDP_TX_TIME ${HAVE_XDP_FLAGS_TX_TIME})
endif()

#
# Check for XDP and Tx HW Timestamp support. It requires: libxdp >= 1.4.1 and Linux v6.8.
#
if ((${LIBXDP_VERSION} GREATER_EQUAL 1.4.1) AND (${HAVE_XDP_FLAGS_TX_HWTSTAMP}))
  message(STATUS "XDP and Tx HW Timestamp support available using libxdp version: ${LIBXDP_VERSION}")
endif()

set(INSTALL_EBPF_DIR ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/rtc-testbench/ebpf)
configure_file(
  "${PROJECT_SOURCE_DIR}/app_config.in"
  "${PROJECT_BINARY_DIR}/app_config.h"
  )
include_directories("${PROJECT_BINARY_DIR}")

#
# Add code for compiling XDP eBPF programes.
#
set(ASM_INCLUDE "/usr/include/${CMAKE_C_LIBRARY_ARCHITECTURE}")
set(CLANG_FLAGS -Wall -O2 -fno-stack-protector
    -I ${ASM_INCLUDE}
    -I ${PROJECT_BINARY_DIR}  # required for app_config.h
)

function(add_xdp_prog name)
  add_custom_target(${name} ALL
    COMMAND clang ${CLANG_FLAGS} -target bpf -c -g -o ${CMAKE_BINARY_DIR}/${name}.o ${name}.c
    DEPENDS reference
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src
    SOURCES src/${name}.c
  )

  install(FILES ${CMAKE_BINARY_DIR}/${name}.o DESTINATION ${CMAKE_INSTALL_LIBDIR}/rtc-testbench/ebpf)
endfunction()

add_xdp_prog(xdp_kern_profinet_vid100)
add_xdp_prog(xdp_kern_opcua_vid100)
add_xdp_prog(xdp_kern_profinet_vid200)
add_xdp_prog(xdp_kern_opcua_vid200)
add_xdp_prog(xdp_kern_opcua_vid300)
add_xdp_prog(xdp_kern_avtp_vid400)
add_xdp_prog(xdp_kern_profinet_veth_dispatch)

install(TARGETS reference DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT binaries)
install(TARGETS mirror DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT binaries)
install(DIRECTORY ${CMAKE_SOURCE_DIR}/tests/ DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/rtc-testbench/tests)

# Add workloads subdirectory for automatic compilation
add_subdirectory(tests/workloads)
