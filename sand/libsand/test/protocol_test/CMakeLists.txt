cmake_minimum_required(VERSION 3.17)
project(protocol_test)

set(TARGET_NAME protocol_test)

include(${SAND_CMAKE_SCRIPTS_DIR}/compiler_options.cmake REQUIRED)

file(GLOB_RECURSE SRC_FILES src/*.cpp)
add_library(${TARGET_NAME} ${SRC_FILES})
target_include_directories(${TARGET_NAME}
        PRIVATE "inc/private"
        PRIVATE "${CMAKE_SOURCE_DIR}/libsand/protocol/inc/private")

find_library(GTEST_LIB gtest REQUIRED)
find_library(GMOCK_LIB gmock REQUIRED)
target_link_libraries(${TARGET_NAME}
        ${GTEST_LIB}
        ${GMOCK_LIB}
        protocol)

message("${CMAKE_SOURCE_DIR}/libsand/protocol/inc/private")
