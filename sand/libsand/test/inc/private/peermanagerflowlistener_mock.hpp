#ifndef SAND_TEST_PEERMANAGERFLOWLISTENER_MOCK_HPP_
#define SAND_TEST_PEERMANAGERFLOWLISTENER_MOCK_HPP_

#include <gmock/gmock.h>

#include "peermanagerflowlistener.hpp"

using namespace ::sand::flows;
using namespace ::sand::network;

class PeerManagerFlowListenerMock : public PeerManagerFlowListener
{
public:
    MOCK_METHOD(void, on_state_changed, (PeerManagerFlow::State), (override));
    MOCK_METHOD(void, on_peer_disconnected, (IPv4Address), (override));
};

#endif  // SAND_TEST_PEERMANAGERFLOWLISTENER_MOCK_HPP_
