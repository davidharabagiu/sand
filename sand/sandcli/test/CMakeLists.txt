cmake_minimum_required(VERSION 3.17)
project(sandcli_test)

set(TARGET_NAME sandc_unit_test)

include(${SAND_CMAKE_SCRIPTS_DIR}/compiler_options.cmake REQUIRED)
include(${SAND_CMAKE_SCRIPTS_DIR}/check_asan.cmake REQUIRED)

file(GLOB_RECURSE SRC_FILES src/*.cpp)
add_executable(${TARGET_NAME} ${SRC_FILES})

find_library(GTEST_LIB gtest REQUIRED)
find_library(GMOCK_LIB gmock REQUIRED)
find_library(GLOG_LIB glog REQUIRED)
target_link_libraries(${TARGET_NAME}
        ${GTEST_LIB}
        ${GMOCK_LIB}
        ${GLOG_LIB}
        pthread
        sandc_impl)

install(TARGETS ${TARGET_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX}/test)
