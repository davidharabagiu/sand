cmake_minimum_required(VERSION 3.17)
project(libsand_api)

set(TARGET_NAME sand)

include(${SAND_CMAKE_SCRIPTS_DIR}/compiler_options.cmake REQUIRED)

file(GLOB_RECURSE SRC_FILES *.cpp)
add_library(${TARGET_NAME} SHARED ${SRC_FILES})

set_target_properties(${TARGET_NAME} PROPERTIES
        SOVERSION ${VERSION})
target_compile_definitions(${TARGET_NAME}
        PRIVATE SAND_BUILD_SHARED_LIB
        PUBLIC SAND_VERSION="${VERSION}")
target_include_directories(${TARGET_NAME}
        PUBLIC "inc/public"
        PRIVATE "inc/private"
        PRIVATE "${CMAKE_SOURCE_DIR}/libsand/config/inc/private"
        PRIVATE "${CMAKE_SOURCE_DIR}/libsand/flows/inc/private"
        PRIVATE "${CMAKE_SOURCE_DIR}/libsand/protocol/inc/private"
        PRIVATE "${CMAKE_SOURCE_DIR}/libsand/network/inc/private"
        PRIVATE "${CMAKE_SOURCE_DIR}/libsand/storage/inc/private"
        PRIVATE "${CMAKE_SOURCE_DIR}/libsand/crypto/inc/private")

find_library(GLOG_LIB glog REQUIRED)
target_link_libraries(${TARGET_NAME}
        ${GLOG_LIB}
        utils
        config
        flows
        protocol
        network
        storage
        crypto)

install(TARGETS ${TARGET_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX}/lib)
install(DIRECTORY inc/public/ DESTINATION include)
