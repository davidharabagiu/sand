cmake_minimum_required(VERSION 3.17)
project(libsand_unit_test)

set(TARGET_NAME sand_unit_test)
set(RES_TARGET_NAME sand_unit_test_res)

include(${SAND_CMAKE_SCRIPTS_DIR}/compiler_options.cmake REQUIRED)
include(${SAND_CMAKE_SCRIPTS_DIR}/check_asan.cmake REQUIRED)

file(GLOB_RECURSE SRC_FILES *.cpp)
add_executable(${TARGET_NAME} ${SRC_FILES})

target_include_directories(${TARGET_NAME}
        PRIVATE "inc/private"
        PRIVATE "${CMAKE_SOURCE_DIR}/libsand/test/mock"
        PRIVATE "${CMAKE_SOURCE_DIR}/libsand/protocol/inc/private"
        PRIVATE "${CMAKE_SOURCE_DIR}/libsand/crypto/inc/private"
        PRIVATE "${CMAKE_SOURCE_DIR}/libsand/network/inc/private"
        PRIVATE "${CMAKE_SOURCE_DIR}/libsand/flows/inc/private"
        PRIVATE "${CMAKE_SOURCE_DIR}/libsand/storage/inc/private"
        PRIVATE "${CMAKE_SOURCE_DIR}/libsand/config/inc/private")

find_library(GTEST_LIB gtest REQUIRED)
find_library(GMOCK_LIB gmock REQUIRED)
find_library(GLOG_LIB glog REQUIRED)
target_link_libraries(${TARGET_NAME}
        ${GTEST_LIB}
        ${GMOCK_LIB}
        ${GLOG_LIB}
        pthread
        network
        protocol
        utils
        flows
        storage
        config)

add_custom_target(${RES_TARGET_NAME} ALL
        COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_CURRENT_SOURCE_DIR}/res/
        ${CMAKE_CURRENT_BINARY_DIR})

install(TARGETS ${TARGET_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX}/test)
install(DIRECTORY res/ DESTINATION ${CMAKE_INSTALL_PREFIX}/test)
