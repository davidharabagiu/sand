#include <gtest/gtest.h>

#include "textfilednlconfigloader.hpp"

using namespace ::testing;
using namespace ::sand::flows;
using namespace ::sand::network;

namespace
{
class TextFileDNLConfigLoaderTest : public Test
{
protected:
    void SetUp() override
    {
    }
};
}  // namespace

TEST_F(TextFileDNLConfigLoaderTest, LoadConfig)
{
    std::set<IPv4Address> expected_nodes {conversion::to_ipv4_address("10.0.0.1"),
        conversion::to_ipv4_address("10.0.0.2"), conversion::to_ipv4_address("10.0.0.3"),
        conversion::to_ipv4_address("10.0.0.4"), conversion::to_ipv4_address("10.0.0.5")};

    TextFileDNLConfigLoader loader {"test/dnl_config.txt"};
    auto                    got_nodes = loader.load();

    EXPECT_EQ(std::set<IPv4Address>(got_nodes.cbegin(), got_nodes.cend()), expected_nodes);
}

TEST_F(TextFileDNLConfigLoaderTest, LoadConfig_FileNotFound)
{
    TextFileDNLConfigLoader loader {"Romeo Fantastik - www sexysexybomba com.mp4"};
    EXPECT_TRUE(loader.load().empty());
}
