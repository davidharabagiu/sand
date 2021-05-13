#include "dnlconfig.hpp"

#include <algorithm>

#include "dnlconfigloader.hpp"

namespace sand::flows
{
DNLConfig::DNLConfig(std::unique_ptr<DNLConfigLoader> loader)
    : loader_ {std::move(loader)}
{
    reload();
}

DNLConfig::~DNLConfig()
{
}

void DNLConfig::reload()
{
    pool_ = loader_->load();
}

network::IPv4Address DNLConfig::random_pick()
{
    if (is_empty())
    {
        return network::conversion::to_ipv4_address("0.0.0.0");
    }
    return pool_[rng_.next<size_t>(pool_.size() - 1)];
}

void DNLConfig::exclude(network::IPv4Address address)
{
    auto it = std::find(pool_.begin(), pool_.end(), address);
    if (it != pool_.end())
    {
        pool_.erase(it);
    }
}

bool DNLConfig::is_empty() const
{
    return pool_.empty();
}
}  // namespace sand::flows
