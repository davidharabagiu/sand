cmake_minimum_required(VERSION 3.17)
project(libsand_hello)

include(${SAND_CMAKE_SCRIPTS_DIR}/compiler_options.cmake REQUIRED)
include(${SAND_CMAKE_SCRIPTS_DIR}/third_party_libs.cmake REQUIRED)

file(GLOB_RECURSE SRC_FILES ${CMAKE_SOURCE_DIR}/libsand/hello *.cpp)
add_library(sand SHARED ${SRC_FILES})

target_compile_definitions(sand PRIVATE SAND_BUILD_SHARED_LIB)
target_include_directories(sand PUBLIC ${CMAKE_SOURCE_DIR}/libsand/include)
use_glog(sand)

install(TARGETS sand DESTINATION ${CMAKE_INSTALL_PREFIX})
install(DIRECTORY ${CMAKE_SOURCE_DIR}/libsand/include DESTINATION .)
