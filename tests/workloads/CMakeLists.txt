# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2025 Intel Corporation
#
# CMakeLists.txt for workloads
#
# Automatically compile all workloads in subdirectories

# Function to create a workload shared library
function(add_workload_library workload_name workload_dir)
    # Check if the workload directory exists and has .c files
    file(GLOB WORKLOAD_SOURCES "${workload_dir}/*.c")

    if(WORKLOAD_SOURCES)
        # Create the shared library target
        add_library(${workload_name} SHARED ${WORKLOAD_SOURCES})

        # Set properties for shared library
        set_target_properties(${workload_name} PROPERTIES
            POSITION_INDEPENDENT_CODE ON
            PREFIX ""  # Remove lib prefix
            SUFFIX ".so"
        )

        # Set compile options
        target_compile_options(${workload_name} PRIVATE
            -Wall
            -Wextra
            -fPIC
            -std=gnu99
        )

        # Allow undefined symbols (they will be resolved by the main application)
        target_link_options(${workload_name} PRIVATE
            -Wl,--allow-shlib-undefined
        )

        # Include the src directory for log.h and other headers
        target_include_directories(${workload_name} PRIVATE
            "${CMAKE_SOURCE_DIR}/src"
        )

        # Set output directory to the workload's directory
        set_target_properties(${workload_name} PROPERTIES
            LIBRARY_OUTPUT_DIRECTORY "${workload_dir}"
        )

        message(STATUS "Added workload: ${workload_name} from ${workload_dir}")
    endif()
endfunction()

# Get all subdirectories in the workloads directory
file(GLOB WORKLOAD_DIRS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "*")

# Process each subdirectory
foreach(WORKLOAD_DIR ${WORKLOAD_DIRS})
    set(FULL_WORKLOAD_DIR "${CMAKE_CURRENT_SOURCE_DIR}/${WORKLOAD_DIR}")

    # Check if it's a directory (not a file)
    if(IS_DIRECTORY "${FULL_WORKLOAD_DIR}")
        # Use the directory name as the workload name
        add_workload_library("${WORKLOAD_DIR}" "${FULL_WORKLOAD_DIR}")
    endif()
endforeach()
