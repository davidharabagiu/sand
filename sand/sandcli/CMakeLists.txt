cmake_minimum_required(VERSION 3.17)
project(sandcli)

set(TARGET_NAME sandc)

include(${SAND_CMAKE_SCRIPTS_DIR}/compiler_options.cmake REQUIRED)
include(${SAND_CMAKE_SCRIPTS_DIR}/check_asan.cmake REQUIRED)

file(GLOB_RECURSE SANDCLI_SOURCES . *.cpp)
add_executable(${TARGET_NAME} ${SANDCLI_SOURCES})

if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    target_compile_definitions(${TARGET_NAME}
            PRIVATE APP_DATA_DIR="$ENV{HOME}/.sand")
else()
    message(SEND_ERROR "Unsupported OS ${CMAKE_SYSTEM_NAME}")
endif()

find_library(GLOG_LIB glog REQUIRED)
target_link_libraries(${TARGET_NAME} sand ${GLOG_LIB})

install(TARGETS ${TARGET_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX}/bin)
