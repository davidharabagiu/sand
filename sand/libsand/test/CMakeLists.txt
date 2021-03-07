cmake_minimum_required(VERSION 3.17)
project(libsand_test)

file(GLOB_RECURSE SRC_FILES ${CMAKE_SOURCE_DIR}/libsand/test *.cpp)

find_library(GTEST_LIB gtest $ENV{GTEST_DIR}/lib)
find_library(GMOCK_LIB gmock $ENV{GTEST_DIR}/lib)

add_executable(sand_test ${SRC_FILES})

target_link_libraries(sand_test
        sand
        ${GTEST_LIB}
        ${GMOCK_LIB})

target_include_directories(sand_test
        PRIVATE ${CMAKE_SOURCE_DIR}/libsand/include
        PRIVATE $ENV{GTEST_DIR}/include)

install(TARGETS sand_test
        DESTINATION ${CMAKE_INSTALL_PREFIX})
