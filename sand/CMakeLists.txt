cmake_minimum_required(VERSION 3.17)
project(sand)

set(SAND_CMAKE_SCRIPTS_DIR ${CMAKE_SOURCE_DIR}/cmake)

add_subdirectory(libsand)
add_subdirectory(sandcli)
