#ifndef SAND_FLOWS_PEERMANAGER_HPP_
#define SAND_FLOWS_PEERMANAGER_HPP_

#include "peeraddressprovider.hpp"

namespace sand::flows
{
class PeerManager : public PeerAddressProvider
{
public:
    PeerManager();
    std::future<std::vector<network::IPv4Address>> get_peers(int count) override;
};
}  // namespace sand::flows

#endif  // SAND_FLOWS_PEERMANAGER_HPP_
