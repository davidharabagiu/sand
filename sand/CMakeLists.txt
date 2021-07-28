cmake_minimum_required(VERSION 3.17)
project(sand)

set(SAND_CMAKE_SCRIPTS_DIR ${CMAKE_SOURCE_DIR}/cmake)

option(ENABLE_ASAN "Enable address sanitizer" OFF)
option(WITH_UNIT_TESTS "Enable building unit tests" ON)
option(WITH_INTEGRATION_TESTS "Enable building integration tests" ON)

add_subdirectory(libsand)
add_subdirectory(sandcli)
add_subdirectory(dnlapp)
