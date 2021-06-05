#ifndef SAND_FLOWS_PEERADDRESSPROVIDER_HPP_
#define SAND_FLOWS_PEERADDRESSPROVIDER_HPP_

#include <future>
#include <set>
#include <vector>

#include "address.hpp"

namespace sand::flows
{
class PeerAddressProvider
{
public:
    virtual ~PeerAddressProvider() = default;

    virtual std::future<std::vector<network::IPv4Address>> get_peers(
        int count, const std::set<network::IPv4Address> &exclude = {}) = 0;
    virtual int  get_peers_count() const                               = 0;
    virtual void remove_peer(network::IPv4Address addr)                = 0;
};
}  // namespace sand::flows

#endif  // SAND_FLOWS_PEERADDRESSPROVIDER_HPP_
