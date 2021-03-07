cmake_minimum_required(VERSION 3.17)
project(sandcli)

file(GLOB_RECURSE SANDCLI_SOURCES ${CMAKE_SOURCE_DIR}/libsand *.cpp)

find_library(GLOG_LIB glog $ENV{GLOG_DIR}/lib)

add_executable(sandc ${SANDCLI_SOURCES})
target_link_libraries(sandc
        sand
        ${GLOG_LIB})
target_include_directories(sandc
        PUBLIC ${CMAKE_SOURCE_DIR}/libsand/include
        PRIVATE $ENV{GLOG_DIR}/include)

install(TARGETS sandc
        DESTINATION ${CMAKE_INSTALL_PREFIX})
