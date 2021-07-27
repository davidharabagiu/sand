#ifndef SAND_TEST_CONFIGLOADER_MOCK_HPP_
#define SAND_TEST_CONFIGLOADER_MOCK_HPP_

#include <gmock/gmock.h>

#include "configloader.hpp"

using namespace ::sand::config;

class ConfigLoaderMock : public ConfigLoader
{
public:
    MOCK_METHOD((std::map<std::string, std::any>), load, (), (const, override));
};

#endif  // SAND_TEST_CONFIGLOADER_MOCK_HPP_
