cmake_minimum_required(VERSION 3.17)
project(libsand_test)

include(${SAND_CMAKE_SCRIPTS_DIR}/compiler_options.cmake REQUIRED)

file(GLOB_RECURSE SRC_FILES ${CMAKE_SOURCE_DIR}/libsand/test *.cpp)
add_executable(sand_test ${SRC_FILES})

target_link_libraries(sand_test sand)
target_include_directories(sand_test PRIVATE ${CMAKE_SOURCE_DIR}/libsand/include)
use_gtest_gmock(sand_test)

install(TARGETS sand_test
        DESTINATION ${CMAKE_INSTALL_PREFIX})
