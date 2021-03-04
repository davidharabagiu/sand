cmake_minimum_required(VERSION 3.17)
project(libsand_hello)

add_compile_definitions(SAND_BUILD_SHARED_LIB)

file(GLOB_RECURSE SRC_FILES ${CMAKE_SOURCE_DIR}/libsand/hello *.cpp)

find_package(Boost 1.75 REQUIRED)

add_library(sand SHARED ${SRC_FILES})

target_link_libraries(sand Boost::boost)
target_include_directories(sand PUBLIC ${CMAKE_SOURCE_DIR}/libsand/include)

install(TARGETS sand
        DESTINATION ${CMAKE_INSTALL_PREFIX})
install(DIRECTORY ${CMAKE_SOURCE_DIR}/libsand/include
        DESTINATION .)
