#ifndef SAND_TEST_PEERADDRESSPROVIDER_MOCK_HPP_
#define SAND_TEST_PEERADDRESSPROVIDER_MOCK_HPP_

#include <gmock/gmock.h>

#include "peeraddressprovider.hpp"

using namespace ::sand::flows;
using namespace ::sand::network;

class PeerAddressProviderMock : public PeerAddressProvider
{
public:
    MOCK_METHOD(std::future<std::vector<IPv4Address>>, get_peers,
        (int, const std::set<IPv4Address> &), (override));
    MOCK_METHOD(int, get_peers_count, (), (const, override));
    MOCK_METHOD(void, remove_peer, (IPv4Address), (override));
};

#endif  // SAND_TEST_PEERADDRESSPROVIDER_MOCK_HPP_
