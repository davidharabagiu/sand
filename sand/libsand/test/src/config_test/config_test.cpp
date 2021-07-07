#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "config.hpp"

#include "configloader_mock.hpp"

using namespace ::testing;
using namespace ::sand::config;

namespace
{
class ConfigTest : public Test
{
protected:
    void SetUp() override
    {
        ON_CALL(config_loader_, load())
            .WillByDefault(Return(std::map<std::string, std::any> {
                {ConfigKey(ConfigKey::PORT).to_string(), network_port_},
                {ConfigKey(ConfigKey::KNOWN_DNL_NODES_LIST_PATH).to_string(),
                    known_dnl_nodes_list_path_},
                {ConfigKey(ConfigKey::IS_DNL_NODE).to_string(), is_dnl_node_},
                {ConfigKey(ConfigKey::SEARCH_TIMEOUT).to_string(), search_timeout_}}));
    }

    NiceMock<ConfigLoaderMock> config_loader_;
    const long long            network_port_              = 8042LL;
    const std::string          known_dnl_nodes_list_path_ = "/home/sciorba/dnl_config.txt";
    const bool                 is_dnl_node_               = false;
    const double               search_timeout_            = 5.5;
};
}  // namespace

TEST_F(ConfigTest, GetInt)
{
    Config conf {config_loader_};
    EXPECT_EQ(conf.get_integer(ConfigKey::PORT), std::make_pair(network_port_, true));
}

TEST_F(ConfigTest, GetString)
{
    Config conf {config_loader_};
    EXPECT_EQ(conf.get_string(ConfigKey::KNOWN_DNL_NODES_LIST_PATH),
        std::make_pair(known_dnl_nodes_list_path_, true));
}

TEST_F(ConfigTest, GetBool)
{
    Config conf {config_loader_};
    EXPECT_EQ(conf.get_bool(ConfigKey::IS_DNL_NODE), std::make_pair(is_dnl_node_, true));
}

TEST_F(ConfigTest, GetFloat)
{
    Config conf {config_loader_};
    EXPECT_EQ(conf.get_float(ConfigKey::SEARCH_TIMEOUT), std::make_pair(search_timeout_, true));
}

TEST_F(ConfigTest, GetMissingValue)
{
    Config conf {config_loader_};
    EXPECT_EQ(conf.get_integer(ConfigKey::INITIAL_PEER_COUNT).second, false);
}

TEST_F(ConfigTest, GetValue_WrongType)
{
    Config conf {config_loader_};
    EXPECT_EQ(conf.get_float(ConfigKey::PORT).second, false);
}
