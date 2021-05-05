cmake_minimum_required(VERSION 3.17)
project(libsand_test)

add_subdirectory(utils_test)
add_subdirectory(protocol_test)

set(TARGET_NAME sand_test)

include(${SAND_CMAKE_SCRIPTS_DIR}/compiler_options.cmake REQUIRED)

file(GLOB_RECURSE SRC_FILES src/*.cpp)
add_executable(${TARGET_NAME} ${SRC_FILES})

find_library(GTEST_LIB gtest REQUIRED)
find_library(GMOCK_LIB gmock REQUIRED)
target_link_libraries(${TARGET_NAME}
        ${GTEST_LIB}
        ${GMOCK_LIB}
        pthread
        utils_test
        protocol_test)

install(TARGETS ${TARGET_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX})
