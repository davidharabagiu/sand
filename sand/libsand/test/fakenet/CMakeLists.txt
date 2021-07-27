cmake_minimum_required(VERSION 3.17)
project(fakenet)

set(TARGET_NAME fakenet)

include(${SAND_CMAKE_SCRIPTS_DIR}/compiler_options.cmake REQUIRED)

file(GLOB_RECURSE SRC_FILES
        src/*.cpp
        ${CMAKE_SOURCE_DIR}/libsand/network/src/address.cpp)
add_library(${TARGET_NAME} ${SRC_FILES})

target_include_directories(${TARGET_NAME}
        PUBLIC "inc/public"
        PUBLIC "${CMAKE_SOURCE_DIR}/libsand/network/inc/public")

find_library(GLOG_LIB glog REQUIRED)
target_link_libraries(${TARGET_NAME}
        ${GLOG_LIB}
        utils)
