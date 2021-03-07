cmake_minimum_required(VERSION 3.17)
project(sandcli)

include(${SAND_CMAKE_SCRIPTS_DIR}/compiler_options.cmake REQUIRED)
include(${SAND_CMAKE_SCRIPTS_DIR}/third_party_libs.cmake REQUIRED)

file(GLOB_RECURSE SANDCLI_SOURCES ${CMAKE_SOURCE_DIR}/libsand *.cpp)
add_executable(sandc ${SANDCLI_SOURCES})

target_link_libraries(sandc sand)
target_include_directories(sandc PUBLIC ${CMAKE_SOURCE_DIR}/libsand/include)
use_glog(sandc)

install(TARGETS sandc DESTINATION ${CMAKE_INSTALL_PREFIX})
