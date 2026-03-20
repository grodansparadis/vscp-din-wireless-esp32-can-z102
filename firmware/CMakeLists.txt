# The following lines of boilerplate have to be in your project's CMakeLists
# in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.22)

# PROJECT_VER must be defined before project() so esp_app_desc.version uses it.
file(READ "${CMAKE_SOURCE_DIR}/build_counter.txt" BUILD_COUNTER_RAW)
string(STRIP "${BUILD_COUNTER_RAW}" BUILD_COUNTER)
if("${BUILD_COUNTER}" STREQUAL "")
    set(BUILD_COUNTER 0)
endif()
math(EXPR BUILD_COUNTER_NEXT "${BUILD_COUNTER} + 1")
set(PROJECT_VER "0.0.1.${BUILD_COUNTER_NEXT}")

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
