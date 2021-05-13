#ifndef SAND_TEST_DNLCONFIGLOADER_MOCK_HPP_
#define SAND_TEST_DNLCONFIGLOADER_MOCK_HPP_

#include <gmock/gmock.h>

#include "dnlconfigloader.hpp"

using namespace ::sand::flows;
using namespace ::sand::network;

class DNLConfigLoaderMock : public DNLConfigLoader
{
public:
    MOCK_METHOD(std::vector<IPv4Address>, load, (), (override));
};

#endif  // SAND_TEST_DNLCONFIGLOADER_MOCK_HPP_
