cmake_minimum_required(VERSION 3.17)
project(sandcli)

file(GLOB_RECURSE SANDCLI_SOURCES ${CMAKE_SOURCE_DIR}/libsand *.cpp)

add_executable(sandc ${SANDCLI_SOURCES})
target_link_libraries(sandc sand)

install(TARGETS sandc
        DESTINATION ${CMAKE_INSTALL_PREFIX})
