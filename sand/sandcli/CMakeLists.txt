cmake_minimum_required(VERSION 3.17)

set(VERSION 1.0)
set(AUTHOR "David Harabagiu")
set(LICENSE "This program and the SAND library are released under the GNU General Public License v3.0 or later")

add_subdirectory(impl)

if (WITH_UNIT_TESTS)
    add_subdirectory(test)
endif()

project(sandcli)

set(TARGET_NAME sandc)

file(READ "config.json" CONFIG_FILE_CONTENT)
string(REPLACE "\n" "\\n" CONFIG_FILE_CONTENT ${CONFIG_FILE_CONTENT})
string(REPLACE "\"" "\\\"" CONFIG_FILE_CONTENT ${CONFIG_FILE_CONTENT})

file(READ "../dnl_node_list.txt" DNL_LIST_FILE_CONTENT)
string(REPLACE "\n" "\\n" DNL_LIST_FILE_CONTENT ${DNL_LIST_FILE_CONTENT})

include(${SAND_CMAKE_SCRIPTS_DIR}/compiler_options.cmake REQUIRED)
include(${SAND_CMAKE_SCRIPTS_DIR}/check_asan.cmake REQUIRED)

add_executable(${TARGET_NAME} main.cpp)

target_compile_definitions(${TARGET_NAME}
        PRIVATE SANDCLI_VERSION="${VERSION}"
        PRIVATE PROGRAM_AUTHOR="${AUTHOR}"
        PRIVATE PROGRAM_LICENSE="${LICENSE}"
        PRIVATE SAND_CONFIGURATION="${CONFIG_FILE_CONTENT}"
        PRIVATE DNL_NODE_LIST_FILE="dnl_node_list.txt"
        PRIVATE DNL_NODE_LIST="${DNL_LIST_FILE_CONTENT}")

find_library(GLOG_LIB glog REQUIRED)
target_link_libraries(${TARGET_NAME}
        ${GLOG_LIB}
        sandc_impl)

install(TARGETS ${TARGET_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX}/bin)
