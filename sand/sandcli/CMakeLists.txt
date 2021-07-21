cmake_minimum_required(VERSION 3.17)

add_subdirectory(impl)
add_subdirectory(test)

project(sandcli)

set(TARGET_NAME sandc)

include(${SAND_CMAKE_SCRIPTS_DIR}/compiler_options.cmake REQUIRED)
include(${SAND_CMAKE_SCRIPTS_DIR}/check_asan.cmake REQUIRED)

add_executable(${TARGET_NAME} main.cpp)

if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    target_compile_definitions(${TARGET_NAME}
            PRIVATE APP_DATA_DIR="$ENV{HOME}/.sand")
else()
    message(SEND_ERROR "Unsupported OS ${CMAKE_SYSTEM_NAME}")
endif()

find_library(GLOG_LIB glog REQUIRED)
target_link_libraries(${TARGET_NAME}
        ${GLOG_LIB}
        sandc_impl)

install(TARGETS ${TARGET_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX}/bin)
