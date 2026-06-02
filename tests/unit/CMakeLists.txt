# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (C) 2026 Linutronix GmbH
#

pkg_search_module(CMOCKA REQUIRED cmocka)

add_executable(ring_buffer_test
  ring_buffer_test.c
  ${CMAKE_SOURCE_DIR}/src/ring_buffer.c)

target_compile_options(ring_buffer_test PRIVATE -Wall -Wextra -Wno-sign-compare -Wshadow -std=gnu99 -Wvla)
target_compile_definitions(ring_buffer_test PRIVATE -D_GNU_SOURCE)

target_include_directories(ring_buffer_test PRIVATE
  ${CMAKE_SOURCE_DIR}/src
  ${PROJECT_BINARY_DIR}
  ${CMOCKA_INCLUDE_DIRS})

target_link_libraries(ring_buffer_test ${CMOCKA_LIBRARIES} Threads::Threads)

add_test(NAME ring_buffer_test COMMAND ring_buffer_test)
