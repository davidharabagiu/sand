cmake_minimum_required(VERSION 3.17)
project(libsand)

set(VERSION 0.9.2)

add_subdirectory(test)
add_subdirectory(utils)
add_subdirectory(protocol)
add_subdirectory(network)
add_subdirectory(crypto)
add_subdirectory(flows)
add_subdirectory(storage)
add_subdirectory(config)
add_subdirectory(api)
