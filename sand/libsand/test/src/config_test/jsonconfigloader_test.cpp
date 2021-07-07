#include <gtest/gtest.h>

#include <fstream>
#include <string>

#include "jsonconfigloader.hpp"

using namespace ::testing;
using namespace ::sand::config;

namespace
{
class JSONConfigLoaderTest : public Test
{
protected:
    const std::string basic_json_config_path      = "test/config_basic.json";
    const std::string multilevel_json_config_path = "test/config_multilevel.json";
};
}  // namespace

TEST_F(JSONConfigLoaderTest, BasicJSON)
{
    JSONConfigLoader ldr {basic_json_config_path};
    auto             vals = ldr.load();

    EXPECT_EQ(vals.size(), 5);
    EXPECT_EQ(std::any_cast<std::string>(vals.at("key0")), "strval");
    EXPECT_EQ(std::any_cast<long long>(vals.at("key1")), 123);
    EXPECT_EQ(std::any_cast<long long>(vals.at("key2")), -10);
    EXPECT_EQ(std::any_cast<double>(vals.at("key3")), 1.55);
    EXPECT_EQ(std::any_cast<bool>(vals.at("key4")), true);
}

TEST_F(JSONConfigLoaderTest, MultilevelJSON)
{
    JSONConfigLoader ldr {multilevel_json_config_path};
    auto             vals = ldr.load();

    EXPECT_EQ(vals.size(), 6);
    EXPECT_EQ(std::any_cast<std::string>(vals.at("key0")), "this is a string");
    EXPECT_EQ(std::any_cast<long long>(vals.at("key1")), -1);
    EXPECT_EQ(std::any_cast<long long>(vals.at("key2")), 1);
    EXPECT_EQ(std::any_cast<double>(vals.at("key3")), -0.1);
    EXPECT_EQ(std::any_cast<double>(vals.at("key4")), 0.1);
    EXPECT_EQ(std::any_cast<bool>(vals.at("key5")), true);
}
