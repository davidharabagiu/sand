cmake_minimum_required(VERSION 3.17)
project(libsand_fnet)

set(TARGET_NAME sand_fakenet)
set(VERSION "${VERSION}_fakenet")

include(${SAND_CMAKE_SCRIPTS_DIR}/compiler_options.cmake REQUIRED)

file(GLOB_RECURSE SRC_FILES
        "${CMAKE_SOURCE_DIR}/libsand/api/src/*.cpp"
        "${CMAKE_SOURCE_DIR}/libsand/config/src/*.cpp"
        "${CMAKE_SOURCE_DIR}/libsand/crypto/src/*.cpp"
        "${CMAKE_SOURCE_DIR}/libsand/flows/src/*.cpp"
        "${CMAKE_SOURCE_DIR}/libsand/protocol/src/*.cpp"
        "${CMAKE_SOURCE_DIR}/libsand/storage/src/*.cpp"
        "${CMAKE_SOURCE_DIR}/libsand/utils/src/*.cpp")
add_library(${TARGET_NAME} ${SRC_FILES})

target_compile_definitions(${TARGET_NAME}
        PRIVATE SAND_BUILD_STATIC_LIB
        PUBLIC SAND_VERSION="${VERSION}")
target_include_directories(${TARGET_NAME}
        PUBLIC "${CMAKE_SOURCE_DIR}/libsand/api/inc/public"
        PRIVATE "${CMAKE_SOURCE_DIR}/libsand/api/inc/private"
        PUBLIC "${CMAKE_SOURCE_DIR}/libsand/config/inc/public"
        PRIVATE "${CMAKE_SOURCE_DIR}/libsand/config/inc/private"
        PUBLIC "${CMAKE_SOURCE_DIR}/libsand/flows/inc/public"
        PRIVATE "${CMAKE_SOURCE_DIR}/libsand/flows/inc/private"
        PUBLIC "${CMAKE_SOURCE_DIR}/libsand/protocol/inc/public"
        PRIVATE "${CMAKE_SOURCE_DIR}/libsand/protocol/inc/private"
        PUBLIC "${CMAKE_SOURCE_DIR}/libsand/storage/inc/public"
        PRIVATE "${CMAKE_SOURCE_DIR}/libsand/storage/inc/private"
        PUBLIC "${CMAKE_SOURCE_DIR}/libsand/crypto/inc/public"
        PRIVATE "${CMAKE_SOURCE_DIR}/libsand/crypto/inc/private"
        PUBLIC "${CMAKE_SOURCE_DIR}/libsand/utils/inc/public"
        PRIVATE "${CMAKE_SOURCE_DIR}/libsand/utils/inc/private")

find_library(GLOG_LIB glog REQUIRED)
find_library(CRYPTO_LIB crypto REQUIRED)
target_link_libraries(${TARGET_NAME}
        ${GLOG_LIB}
        ${CRYPTO_LIB}
        fakenet)
