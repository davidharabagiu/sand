#ifndef SAND_TEST_DNLFLOWLISTENER_MOCK_HPP_
#define SAND_TEST_DNLFLOWLISTENER_MOCK_HPP_

#include <gmock/gmock.h>

#include "dnlflowlistener.hpp"

using namespace ::sand::flows;
using namespace ::sand::network;

class DNLFlowListenerMock : public DNLFlowListener
{
public:
    MOCK_METHOD(void, on_state_changed, (DNLFlow::State), (override));
    MOCK_METHOD(void, on_node_connected, (IPv4Address), (override));
    MOCK_METHOD(void, on_node_disconnected, (IPv4Address), (override));
};

#endif  // SAND_TEST_DNLFLOWLISTENER_MOCK_HPP_
