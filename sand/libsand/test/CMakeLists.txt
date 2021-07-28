cmake_minimum_required(VERSION 3.17)

if (WITH_UNIT_TESTS)
    add_subdirectory(unit_test)
endif()

if (WITH_INTEGRATION_TESTS)
    add_subdirectory(fakenet)
    add_subdirectory(libsand_fnet)
    add_subdirectory(integration_test_fnet)
endif()
