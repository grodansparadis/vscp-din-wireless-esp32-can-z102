# The following lines of boilerplate have to be in your project's CMakeLists
# in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.22)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(vscp_can4vscp_gw)

set(BUILD_COUNTER_HEADER ${CMAKE_BINARY_DIR}/build_counter.h)

add_custom_command(
    OUTPUT ${BUILD_COUNTER_HEADER}
    COMMAND ${CMAKE_COMMAND} -E env python ${CMAKE_SOURCE_DIR}/tools/increment_build.py
    DEPENDS ${CMAKE_SOURCE_DIR}/build_counter.txt
    COMMENT "Incrementing build counter"
)

add_custom_target(build_counter ALL DEPENDS ${BUILD_COUNTER_HEADER})

add_dependencies(${PROJECT_NAME}.elf build_counter)

include_directories(${CMAKE_BINARY_DIR})

set(PROJECT_VER "0.0.1.${BUILD_COUNTER}")
