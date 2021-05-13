#ifndef SAND_FLOWS_PEERADDRESSPROVIDER_HPP_
#define SAND_FLOWS_PEERADDRESSPROVIDER_HPP_

#include <future>
#include <vector>

#include "address.hpp"

namespace sand::flows
{
class PeerAddressProvider
{
public:
    virtual ~PeerAddressProvider() = default;

    virtual std::future<std::vector<network::IPv4Address>> get_peers(int count) = 0;
};
}  // namespace sand::flows

#endif  // SAND_FLOWS_PEERADDRESSPROVIDER_HPP_
