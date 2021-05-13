#ifndef SAND_TEST_PROTOCOLMESSAGEHANDLER_MOCK_HPP_
#define SAND_TEST_PROTOCOLMESSAGEHANDLER_MOCK_HPP_

#include <gmock/gmock.h>

#include "messages.hpp"
#include "protocolmessagehandler.hpp"

using namespace ::testing;
using namespace ::sand::protocol;
using namespace ::sand::network;

class ProtocolMessageHandlerMock : public ProtocolMessageHandler
{
public:
    MOCK_METHOD(bool, register_message_listener, (const std::shared_ptr<ProtocolMessageListener> &),
        (override));
    MOCK_METHOD(bool, unregister_message_listener,
        (const std::shared_ptr<ProtocolMessageListener> &), (override));
    MOCK_METHOD(std::future<std::unique_ptr<BasicReply>>, send,
        (IPv4Address, std::unique_ptr<sand::protocol::Message>), (override));
    MOCK_METHOD(
        std::future<bool>, send_reply, (IPv4Address, std::unique_ptr<BasicReply>), (override));
};

#endif  // SAND_TEST_PROTOCOLMESSAGEHANDLER_MOCK_HPP_
