#include "dnlconfig.hpp"

#include <algorithm>

#include "dnlconfigloader.hpp"

namespace sand::config
{
DNLConfig::DNLConfig(std::unique_ptr<DNLConfigLoader> loader)
    : loader_ {std::move(loader)}
{
    reload();
}

DNLConfig::~DNLConfig()
{}

void DNLConfig::reload()
{
    std::lock_guard lock {mutex_};
    pool_ = loader_->load();
}

network::IPv4Address DNLConfig::random_pick()
{
    std::lock_guard lock {mutex_};
    if (pool_.empty())
    {
        return network::conversion::to_ipv4_address("0.0.0.0");
    }
    return pool_[rng_.next<size_t>(pool_.size() - 1)];
}

void DNLConfig::exclude(network::IPv4Address address)
{
    std::lock_guard lock {mutex_};
    auto            it = std::find(pool_.begin(), pool_.end(), address);
    if (it != pool_.end())
    {
        pool_.erase(it);
    }
}

bool DNLConfig::is_empty() const
{
    std::lock_guard lock {mutex_};
    return pool_.empty();
}

std::vector<network::IPv4Address> DNLConfig::get_all() const
{
    std::lock_guard lock {mutex_};
    return pool_;
}

bool DNLConfig::contains(network::IPv4Address address) const
{
    std::lock_guard lock {mutex_};
    return std::find(pool_.cbegin(), pool_.cend(), address) != pool_.cend();
}
}  // namespace sand::config
