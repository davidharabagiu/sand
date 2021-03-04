cmake_minimum_required(VERSION 3.17)
project(libsand_test)

file(GLOB_RECURSE SRC_FILES ${CMAKE_SOURCE_DIR}/libsand/test *.cpp)

find_package(GTest 1.10 REQUIRED)

add_executable(sand_test ${SRC_FILES})

target_link_libraries(sand_test sand)
target_link_libraries(sand_test GTest::gtest GTest::gtest_main)

install(TARGETS sand_test
        DESTINATION ${CMAKE_INSTALL_PREFIX})
