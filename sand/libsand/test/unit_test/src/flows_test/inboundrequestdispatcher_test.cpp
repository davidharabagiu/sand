#include <gtest/gtest.h>

#include <memory>

#include "inboundrequestdispatcher.hpp"
#include "testutils.hpp"

#include "protocolmessagehandler_mock.hpp"

using namespace ::testing;
using namespace ::sand::flows;
using namespace ::sand::protocol;
using namespace ::sand::network;

namespace
{
class InboundRequestDispatcherTest : public Test
{
protected:
    void SetUp() override
    {
        msg_handler_ = std::make_shared<NiceMock<ProtocolMessageHandlerMock>>();
    }

    std::shared_ptr<ProtocolMessageHandlerMock> msg_handler_;
};
}  // namespace

TEST_F(InboundRequestDispatcherTest, RegistersAsMessageListener)
{
    auto dispatcher = std::make_shared<InboundRequestDispatcher>(msg_handler_);
    EXPECT_CALL(*msg_handler_, register_message_listener(SmartPointerCompare(dispatcher.get())))
        .Times(1)
        .WillOnce(Return(true));
    dispatcher->initialize();
}

TEST_F(InboundRequestDispatcherTest, UnregistersAsMessageListener)
{
    auto dispatcher = std::make_shared<InboundRequestDispatcher>(msg_handler_);
    EXPECT_CALL(*msg_handler_, unregister_message_listener(SmartPointerCompare(dispatcher.get())))
        .Times(1)
        .WillOnce(Return(true));
    dispatcher->uninitialize();
}

TEST_F(InboundRequestDispatcherTest, SetCallback_One)
{
    IPv4Address from = conversion::to_ipv4_address("10.0.0.1");
    PullMessage msg;
    msg.request_id    = 1;
    msg.address_count = 10;

    auto dispatcher = std::make_shared<InboundRequestDispatcher>(msg_handler_);

    bool callback_called = false;
    dispatcher->set_callback<PullMessage>([&](IPv4Address a_from, const PullMessage &a_msg) {
        callback_called = true;
        EXPECT_EQ(from, a_from);
        EXPECT_EQ(msg.request_id, a_msg.request_id);
        EXPECT_EQ(msg.address_count, a_msg.address_count);
    });

    dispatcher->on_message_received(from, msg);
    EXPECT_TRUE(callback_called);
}

TEST_F(InboundRequestDispatcherTest, SetCallback_Multiple)
{
    IPv4Address from1 = conversion::to_ipv4_address("10.0.0.1");
    IPv4Address from2 = conversion::to_ipv4_address("10.0.0.2");
    PullMessage msg1;
    msg1.request_id    = 1;
    msg1.address_count = 10;
    PingMessage msg2;
    msg2.request_id = 2;

    auto dispatcher = std::make_shared<InboundRequestDispatcher>(msg_handler_);

    bool callback1_called = false;
    dispatcher->set_callback<PullMessage>([&](IPv4Address a_from, const PullMessage &a_msg) {
        callback1_called = true;
        EXPECT_EQ(from1, a_from);
        EXPECT_EQ(msg1.request_id, a_msg.request_id);
        EXPECT_EQ(msg1.address_count, a_msg.address_count);
    });

    bool callback2_called = false;
    dispatcher->set_callback<PingMessage>([&](IPv4Address a_from, const PingMessage &a_msg) {
        callback2_called = true;
        EXPECT_EQ(from2, a_from);
        EXPECT_EQ(msg2.request_id, a_msg.request_id);
    });

    dispatcher->on_message_received(from1, msg1);
    dispatcher->on_message_received(from2, msg2);
    EXPECT_TRUE(callback1_called);
    EXPECT_TRUE(callback2_called);
}

TEST_F(InboundRequestDispatcherTest, SetCallback_Replace)
{
    IPv4Address from = conversion::to_ipv4_address("10.0.0.1");
    PullMessage msg;
    msg.request_id    = 1;
    msg.address_count = 10;

    auto dispatcher = std::make_shared<InboundRequestDispatcher>(msg_handler_);

    bool callback1_called = false;
    dispatcher->set_callback<PullMessage>(
        [&](IPv4Address /*a_from*/, const PullMessage & /*a_msg*/) { callback1_called = true; });

    bool callback2_called = false;
    dispatcher->set_callback<PullMessage>([&](IPv4Address a_from, const PullMessage &a_msg) {
        callback2_called = true;
        EXPECT_EQ(from, a_from);
        EXPECT_EQ(msg.request_id, a_msg.request_id);
        EXPECT_EQ(msg.address_count, a_msg.address_count);
    });

    dispatcher->on_message_received(from, msg);
    EXPECT_FALSE(callback1_called);
    EXPECT_TRUE(callback2_called);
}

TEST_F(InboundRequestDispatcherTest, UnsetCallback)
{
    IPv4Address from1 = conversion::to_ipv4_address("10.0.0.1");
    IPv4Address from2 = conversion::to_ipv4_address("10.0.0.2");
    PullMessage msg1;
    PingMessage msg2;

    auto dispatcher = std::make_shared<InboundRequestDispatcher>(msg_handler_);

    bool callback1_called = false;
    dispatcher->set_callback<PullMessage>(
        [&](IPv4Address /*a_from*/, const PullMessage & /*a_msg*/) { callback1_called = true; });

    bool callback2_called = false;
    dispatcher->set_callback<PingMessage>(
        [&](IPv4Address /*a_from*/, const PingMessage & /*a_msg*/) { callback2_called = true; });

    dispatcher->unset_callback<PullMessage>();

    dispatcher->on_message_received(from1, msg1);
    dispatcher->on_message_received(from2, msg2);
    EXPECT_FALSE(callback1_called);
    EXPECT_TRUE(callback2_called);
}
