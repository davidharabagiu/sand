cmake_minimum_required(VERSION 3.17)
project(libsand)

add_compile_definitions(SAND_BUILD_SHARED_LIB)

file(GLOB_RECURSE LIBSAND_SOURCES ${CMAKE_SOURCE_DIR}/libsand *.cpp)

add_library(sand SHARED ${LIBSAND_SOURCES})
target_include_directories(sand PUBLIC include)

install(TARGETS sand
        DESTINATION ${CMAKE_INSTALL_PREFIX})
install(DIRECTORY ${CMAKE_SOURCE_DIR}/libsand/include
        DESTINATION .)
