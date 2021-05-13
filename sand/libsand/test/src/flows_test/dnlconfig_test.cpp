#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <memory>
#include <set>

#include "dnlconfig.hpp"

#include "dnlconfigloader_mock.hpp"

using namespace ::testing;
using namespace ::sand::flows;
using namespace ::sand::network;

namespace
{
class DNLConfigTest : public Test
{
protected:
    void SetUp() override
    {
        loader_        = std::make_unique<NiceMock<DNLConfigLoaderMock>>();
        dnl_node_list_ = {conversion::to_ipv4_address("10.0.0.1"),
            conversion::to_ipv4_address("10.0.0.2"), conversion::to_ipv4_address("10.0.0.3"),
            conversion::to_ipv4_address("10.0.0.4"), conversion::to_ipv4_address("10.0.0.5")};
    }

    std::unique_ptr<DNLConfigLoaderMock> loader_;
    std::vector<IPv4Address>             dnl_node_list_;
};
}  // namespace

TEST_F(DNLConfigTest, CallsLoader)
{
    EXPECT_CALL(*loader_, load()).Times(1);
    DNLConfig config {std::move(loader_)};
}

TEST_F(DNLConfigTest, RandomPick)
{
    ON_CALL(*loader_, load()).WillByDefault(Return(dnl_node_list_));
    DNLConfig config {std::move(loader_)};

    size_t                remaining_tries = dnl_node_list_.size() * 10;
    std::set<IPv4Address> unpicked_nodes(dnl_node_list_.cbegin(), dnl_node_list_.cend());
    while (remaining_tries-- && !unpicked_nodes.empty())
    {
        unpicked_nodes.erase(config.random_pick());
    }

    EXPECT_TRUE(unpicked_nodes.empty());
}

TEST_F(DNLConfigTest, Exclude)
{
    ON_CALL(*loader_, load()).WillByDefault(Return(dnl_node_list_));
    DNLConfig config {std::move(loader_)};

    IPv4Address excluded        = dnl_node_list_[0];
    size_t      remaining_tries = dnl_node_list_.size() * 10;
    config.exclude(excluded);

    while (remaining_tries--)
    {
        EXPECT_NE(config.random_pick(), excluded);
    }
}

TEST_F(DNLConfigTest, ReloadConfig)
{
    ON_CALL(*loader_, load()).WillByDefault(Return(dnl_node_list_));
    DNLConfig config {std::move(loader_)};

    IPv4Address excluded = dnl_node_list_[0];
    config.exclude(excluded);
    config.reload();

    size_t remaining_tries = dnl_node_list_.size() * 10;

    bool not_found = true;
    while (remaining_tries-- && (not_found = (config.random_pick() != excluded)))
        ;

    EXPECT_FALSE(not_found);
}

TEST_F(DNLConfigTest, Empty_LoadFails)
{
    ON_CALL(*loader_, load()).WillByDefault(Return(std::vector<IPv4Address>()));
    DNLConfig config {std::move(loader_)};
    EXPECT_TRUE(config.is_empty());
}

TEST_F(DNLConfigTest, Empty_AllExcluded)
{
    ON_CALL(*loader_, load()).WillByDefault(Return(dnl_node_list_));
    DNLConfig config {std::move(loader_)};

    for (IPv4Address node : dnl_node_list_)
    {
        config.exclude(node);
    }

    EXPECT_TRUE(config.is_empty());
}
