cmake_minimum_required(VERSION 3.17)
project(libsand_network)

set(TARGET_NAME network)

include(${SAND_CMAKE_SCRIPTS_DIR}/compiler_options.cmake REQUIRED)

file(GLOB_RECURSE SRC_FILES src *.cpp)
add_library(${TARGET_NAME} ${SRC_FILES})

find_library(GLOG_LIB glog REQUIRED)
find_package(Boost 1.75.0 COMPONENTS asio)

target_include_directories(${TARGET_NAME}
        PUBLIC inc/public
        PRIVATE inc/private
        PRIVATE ${Boost_INCLUDE_DIRS})
target_link_libraries(${TARGET_NAME}
        ${GLOG_LIB}
        utils)
