cmake_minimum_required(VERSION 3.17)

project(sandcli_impl)

set(TARGET_NAME sandc_impl)

include(${SAND_CMAKE_SCRIPTS_DIR}/compiler_options.cmake REQUIRED)

file(GLOB_RECURSE SRC_FILES src/*.cpp)
add_library(${TARGET_NAME} ${SRC_FILES})

target_include_directories(${TARGET_NAME}
        PUBLIC "inc/public")

find_library(GLOG_LIB glog REQUIRED)
target_link_libraries(${TARGET_NAME}
        sand
        ${GLOG_LIB})
