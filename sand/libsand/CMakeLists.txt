cmake_minimum_required(VERSION 3.17)
project(libsand)

add_compile_definitions(SAND_BUILD_SHARED_LIB)

file(GLOB_RECURSE LIBSAND_SOURCES ${CMAKE_SOURCE_DIR}/libsand *.cpp)

find_package(Boost 1.75 REQUIRED)

add_library(sand SHARED ${LIBSAND_SOURCES})
target_link_libraries(sand ${Boost_LIBRARIES})
target_include_directories(sand PUBLIC include)
target_include_directories(sand PRIVATE ${Boost_INCLUDE_DIRS})

install(TARGETS sand
        DESTINATION ${CMAKE_INSTALL_PREFIX})
install(DIRECTORY ${CMAKE_SOURCE_DIR}/libsand/include
        DESTINATION .)
