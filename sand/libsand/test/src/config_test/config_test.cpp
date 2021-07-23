#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <memory>

#include "config.hpp"
#include "fallbackconfigvalueprovider.hpp"
#include "unused.hpp"

#include "configloader_mock.hpp"

using namespace ::testing;
using namespace ::sand::config;

namespace
{
class ConfigTest : public Test
{
protected:
    class GoodFallbackValueProviderMock : public FallbackConfigValueProvider
    {
    public:
        [[nodiscard]] std::any get(const ConfigKey &key) const override
        {
            if (key == ConfigKey::INITIAL_PEER_COUNT)
            {
                return initial_peer_count_;
            }
            else if (key == ConfigKey::FILE_STORAGE_DIR)
            {
                return std::string {file_storage_path_};
            }
            return {};
        }

        static constexpr long long   initial_peer_count_ = 10LL;
        static constexpr char const *file_storage_path_  = "/home/anon/.sand/storage";
    };

    class BadFallbackValueProviderMock : public FallbackConfigValueProvider
    {
    public:
        [[nodiscard]] std::any get(const ConfigKey &) const override
        {
            return {};
        }
    };

    class BadFallbackValueProviderMock2 : public FallbackConfigValueProvider
    {
    public:
        [[nodiscard]] std::any get(const ConfigKey &key) const override
        {
            if (key == ConfigKey::FILE_STORAGE_DIR)
            {
                return {5};
            }
            return {};
        }
    };

    void SetUp() override
    {
        ON_CALL(config_loader_, load())
            .WillByDefault(Return(std::map<std::string, std::any> {
                {ConfigKey(ConfigKey::PORT).to_string(), network_port_},
                {ConfigKey(ConfigKey::KNOWN_DNL_NODES_LIST_FILE).to_string(),
                    known_dnl_nodes_list_path_},
                {ConfigKey(ConfigKey::IS_DNL_NODE).to_string(), is_dnl_node_},
                {ConfigKey(ConfigKey::SEARCH_TIMEOUT).to_string(), search_timeout_},
                {ConfigKey(ConfigKey::FILE_STORAGE_DIR).to_string(), file_storage_path_}}));
    }

    NiceMock<ConfigLoaderMock> config_loader_;

    const long long   network_port_              = 8042LL;
    const std::string known_dnl_nodes_list_path_ = "/home/sciorba/dnl_config.txt";
    const bool        is_dnl_node_               = false;
    const double      search_timeout_            = 5.5;
    const bool        file_storage_path_         = false;
};
}  // namespace

TEST_F(ConfigTest, GetInt)
{
    Config conf {config_loader_};
    EXPECT_EQ(conf.get_integer(ConfigKey::PORT), network_port_);
}

TEST_F(ConfigTest, GetString)
{
    Config conf {config_loader_};
    EXPECT_EQ(conf.get_string(ConfigKey::KNOWN_DNL_NODES_LIST_FILE), known_dnl_nodes_list_path_);
}

TEST_F(ConfigTest, GetBool)
{
    Config conf {config_loader_};
    EXPECT_EQ(conf.get_bool(ConfigKey::IS_DNL_NODE), is_dnl_node_);
}

TEST_F(ConfigTest, GetFloat)
{
    Config conf {config_loader_};
    EXPECT_EQ(conf.get_float(ConfigKey::SEARCH_TIMEOUT), search_timeout_);
}

TEST_F(ConfigTest, GetMissingValue)
{
    Config conf {config_loader_, std::make_unique<GoodFallbackValueProviderMock>()};
    EXPECT_EQ(conf.get_integer(ConfigKey::INITIAL_PEER_COUNT),
        GoodFallbackValueProviderMock::initial_peer_count_);
}

TEST_F(ConfigTest, GetMissingValue_NoFallback)
{
    Config conf {config_loader_};
    EXPECT_DEATH(UNUSED(conf.get_integer(ConfigKey::INITIAL_PEER_COUNT)), "");
}

TEST_F(ConfigTest, GetMissingValue_MissingInFallback)
{
    Config conf {config_loader_, std::make_unique<BadFallbackValueProviderMock>()};
    EXPECT_DEATH(UNUSED(conf.get_integer(ConfigKey::INITIAL_PEER_COUNT)), "");
}

TEST_F(ConfigTest, GetValue_WrongType)
{
    Config conf {config_loader_, std::make_unique<GoodFallbackValueProviderMock>()};
    EXPECT_EQ(conf.get_string(ConfigKey::FILE_STORAGE_DIR),
        GoodFallbackValueProviderMock::file_storage_path_);
}

TEST_F(ConfigTest, GetValue_WrongType_NoFallback)
{
    Config conf {config_loader_};
    EXPECT_DEATH(UNUSED(conf.get_string(ConfigKey::FILE_STORAGE_DIR)), "");
}

TEST_F(ConfigTest, GetValue_WrongType_MissingInFallback)
{
    Config conf {config_loader_, std::make_unique<BadFallbackValueProviderMock>()};
    EXPECT_DEATH(UNUSED(conf.get_string(ConfigKey::FILE_STORAGE_DIR)), "");
}

TEST_F(ConfigTest, GetValue_WrongType_WrongTypeInCallback)
{
    Config conf {config_loader_, std::make_unique<BadFallbackValueProviderMock2>()};
    EXPECT_DEATH(UNUSED(conf.get_string(ConfigKey::FILE_STORAGE_DIR)), "");
}
