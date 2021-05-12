#ifndef SAND_TEST_TCPMESSAGELISTENER_MOCK_HPP_
#define SAND_TEST_TCPMESSAGELISTENER_MOCK_HPP_

#include <gmock/gmock.h>

#include "tcpmessagelistener.hpp"

using namespace ::sand::network;

class TCPMessageListenerMock : public TCPMessageListener
{
public:
    MOCK_METHOD(void, on_message_received, (IPv4Address, const uint8_t *, size_t), (override));
};

#endif  // SAND_TEST_TCPMESSAGELISTENER_MOCK_HPP_
