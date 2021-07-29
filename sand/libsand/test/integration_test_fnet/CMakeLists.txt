cmake_minimum_required(VERSION 3.17)
project(libsand_integration_test_fnet)

set(TARGET_NAME sand_integration_test_fakenet)

include(${SAND_CMAKE_SCRIPTS_DIR}/compiler_options.cmake REQUIRED)
include(${SAND_CMAKE_SCRIPTS_DIR}/check_asan.cmake REQUIRED)

file(GLOB_RECURSE SRC_FILES *.cpp)
add_executable(${TARGET_NAME} ${SRC_FILES})

find_library(GTEST_LIB gtest REQUIRED)
find_library(GMOCK_LIB gmock REQUIRED)
find_library(GLOG_LIB glog REQUIRED)
target_link_libraries(${TARGET_NAME}
        ${GTEST_LIB}
        ${GMOCK_LIB}
        ${GLOG_LIB}
        pthread
        sand_fakenet
        fakenet)

install(TARGETS ${TARGET_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX}/test)
