#include "peermanager.hpp"

namespace sand::flows
{
PeerManager::PeerManager()
{
}

std::future<std::vector<network::IPv4Address>> PeerManager::get_peers(int /*count*/)
{
    return {};
}
}  // namespace sand::flows
