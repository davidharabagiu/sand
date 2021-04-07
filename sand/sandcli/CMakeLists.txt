cmake_minimum_required(VERSION 3.17)
project(sandcli)

set(TARGET_NAME sandc)

include(${SAND_CMAKE_SCRIPTS_DIR}/compiler_options.cmake REQUIRED)

file(GLOB_RECURSE SANDCLI_SOURCES . *.cpp)
add_executable(${TARGET_NAME} ${SANDCLI_SOURCES})

target_include_directories(sandc PUBLIC ${CMAKE_SOURCE_DIR}/libsand/include)

find_library(GLOG_LIB glog REQUIRED)
target_link_libraries(${TARGET_NAME} sand ${GLOG_LIB})

install(TARGETS ${TARGET_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX})
