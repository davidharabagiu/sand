#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <thread>

#include "protocolmessagehandlerimpl.hpp"
#include "random.hpp"
#include "testutils.hpp"

#include "messageserializer_mock.hpp"
#include "protocolmessagelistener_mock.hpp"
#include "tcpsender_mock.hpp"
#include "tcpserver_mock.hpp"

using namespace ::testing;
using namespace sand::protocol;
using namespace sand::utils;

namespace
{
class ProtocolMessageHandlerTest : public Test
{
protected:
    void SetUp() override
    {
        tcp_sender_ = std::make_shared<NiceMock<TCPSenderMock>>();
        tcp_server_ = std::make_shared<NiceMock<TCPServerMock>>();
        serializer_ = std::make_shared<NiceMock<MessageSerializerMock>>();
        listener_   = std::make_shared<NiceMock<ProtocolMessageListenerMock>>();
    }

    std::shared_ptr<TCPSenderMock>               tcp_sender_;
    std::shared_ptr<TCPServerMock>               tcp_server_;
    std::shared_ptr<MessageSerializerMock>       serializer_;
    std::shared_ptr<ProtocolMessageListenerMock> listener_;
};
}  // namespace

MATCHER_P(
    CArrayEqContainer, container, "Equality comparison of C-style array with a standard container")
{
    return std::equal(container.cbegin(), container.cend(), arg);
}

MATCHER_P(SmartPointerCompare, rhs, "Compares a smart pointer to a raw pointer")
{
    return arg.get() == rhs;
}

TEST_F(ProtocolMessageHandlerTest, RegistersForInboundTCPMessages)
{
    auto uut = std::make_shared<ProtocolMessageHandlerImpl>(tcp_sender_, tcp_server_, serializer_);
    EXPECT_CALL(*tcp_server_, register_listener(SmartPointerCompare(uut.get()))).Times(1);
    uut->initialize();
}

TEST_F(ProtocolMessageHandlerTest, UnregistersFromInboundTCPMessages)
{
    auto uut = std::make_shared<ProtocolMessageHandlerImpl>(tcp_sender_, tcp_server_, serializer_);
    uut->initialize();
    EXPECT_CALL(*tcp_server_, unregister_listener(SmartPointerCompare(uut.get()))).Times(1);
    uut->uninitialize();
}

TEST_F(ProtocolMessageHandlerTest, SendAndReceiveReply)
{
    Random rng;

    IPv4Address p1 = conversion::to_ipv4_address("192.168.0.1");
    IPv4Address p2 = conversion::to_ipv4_address("192.168.0.2");
    IPv4Address p3 = conversion::to_ipv4_address("192.168.0.3");

    PullMessage request;
    request.request_id    = rng.next<RequestId>();
    request.address_count = 10;

    PullReply reply;
    reply.request_id  = request.request_id;
    reply.status_code = StatusCode::OK;
    reply.peers       = {p2, p3};

    std::vector<std::uint8_t> request_bytes {0x01, 0x02, 0x03};
    std::vector<std::uint8_t> reply_bytes {0x04, 0x05, 0x06};

    auto uut = std::make_shared<ProtocolMessageHandlerImpl>(tcp_sender_, tcp_server_, serializer_);

    EXPECT_CALL(*serializer_, serialize(Matcher<const PullMessage &>(
                                  AllOf(Field(&PullMessage::message_code, request.message_code),
                                      Field(&PullMessage::request_id, request.request_id),
                                      Field(&PullMessage::address_count, request.address_count)))))
        .Times(1)
        .WillOnce(Return(request_bytes));
    EXPECT_CALL(*serializer_, deserialize(reply_bytes, _))
        .Times(1)
        .WillOnce(
            [&](const std::vector<uint8_t> &, MessageDeserializationResultReceptor &receptor) {
                receptor.deserialized(reply);
            });
    EXPECT_CALL(*tcp_sender_, send(p1, CArrayEqContainer(request_bytes), request_bytes.size()))
        .Times(1)
        .WillOnce(Return(true));

    auto future = uut->send(p1, request);
    EXPECT_TRUE(future.valid());

    std::thread reply_thread {
        [&] { uut->on_message_received(p1, reply_bytes.data(), reply_bytes.size()); }};

    auto got_reply      = future.get();
    auto got_pull_reply = dynamic_cast<PullReply *>(got_reply.get());

    EXPECT_NE(got_pull_reply, nullptr);
    EXPECT_EQ(reply.message_code, got_pull_reply->message_code);
    EXPECT_EQ(reply.request_id, got_pull_reply->request_id);
    EXPECT_EQ(reply.status_code, got_pull_reply->status_code);
    EXPECT_EQ(reply.request_message_code, got_pull_reply->request_message_code);
    EXPECT_EQ(reply.peers, got_pull_reply->peers);

    reply_thread.join();
}

TEST_F(ProtocolMessageHandlerTest, SendByeMessage)
{
    Random rng;

    IPv4Address p1 = conversion::to_ipv4_address("192.168.0.1");

    ByeMessage msg;
    msg.request_id = rng.next<RequestId>();
    std::vector<std::uint8_t> msg_bytes {0x01, 0x02, 0x03};

    auto uut = std::make_shared<ProtocolMessageHandlerImpl>(tcp_sender_, tcp_server_, serializer_);

    EXPECT_CALL(*serializer_, serialize(Matcher<const ByeMessage &>(
                                  AllOf(Field(&ByeMessage::message_code, msg.message_code),
                                      Field(&ByeMessage::request_id, msg.request_id)))))
        .Times(1)
        .WillOnce(Return(msg_bytes));
    EXPECT_CALL(*tcp_sender_, send(p1, CArrayEqContainer(msg_bytes), msg_bytes.size()))
        .Times(1)
        .WillOnce(Return(true));

    auto future = uut->send(p1, msg);
    EXPECT_TRUE(future.valid());
    auto reply = future.get();

    EXPECT_EQ(reply, nullptr);
}

TEST_F(ProtocolMessageHandlerTest, Send_DuplicateRequestId)
{
    Random rng;

    IPv4Address p1 = conversion::to_ipv4_address("192.168.0.1");
    IPv4Address p2 = conversion::to_ipv4_address("192.168.0.2");

    PushMessage request;
    request.request_id = rng.next<RequestId>();
    std::vector<std::uint8_t> request_bytes {0x01, 0x02, 0x03};

    auto uut = std::make_shared<ProtocolMessageHandlerImpl>(tcp_sender_, tcp_server_, serializer_);

    ON_CALL(*serializer_, serialize(A<const PushMessage &>())).WillByDefault(Return(request_bytes));
    EXPECT_CALL(*tcp_sender_, send(p1, _, _)).Times(1).WillOnce(Return(true));
    EXPECT_CALL(*tcp_sender_, send(p2, _, _)).Times(0);

    auto future1 = uut->send(p1, request);
    auto future2 = uut->send(p2, request);

    EXPECT_TRUE(future1.valid());
    EXPECT_FALSE(future2.valid());
}

TEST_F(ProtocolMessageHandlerTest, Send_PeerUnreachable)
{
    Random rng;

    IPv4Address p1 = conversion::to_ipv4_address("192.168.0.1");

    PushMessage request;
    request.request_id = rng.next<RequestId>();
    std::vector<std::uint8_t> request_bytes {0x01, 0x02, 0x03};

    auto uut = std::make_shared<ProtocolMessageHandlerImpl>(tcp_sender_, tcp_server_, serializer_);

    ON_CALL(*serializer_, serialize(A<const PushMessage &>())).WillByDefault(Return(request_bytes));
    EXPECT_CALL(*tcp_sender_, send(p1, _, _)).Times(1).WillOnce(Return(false));

    auto future = uut->send(p1, request);
    EXPECT_TRUE(future.valid());

    auto reply = future.get();
    EXPECT_NE(reply, nullptr);
    EXPECT_EQ(reply->message_code, MessageCode::REPLY);
    EXPECT_EQ(reply->request_id, request.request_id);
    EXPECT_EQ(reply->request_message_code, request.message_code);
    EXPECT_EQ(reply->status_code, StatusCode::UNREACHABLE);
}

TEST_F(ProtocolMessageHandlerTest, SendAndReceiveStrayReply)
{
    Random rng;

    IPv4Address p1 = conversion::to_ipv4_address("192.168.0.1");

    PushMessage request;
    request.request_id = rng.next<RequestId>();

    BasicReply reply {request.message_code};
    reply.request_id  = rng.next<RequestId>();
    reply.status_code = StatusCode::OK;

    std::vector<std::uint8_t> request_bytes {0x01, 0x02, 0x03};
    std::vector<std::uint8_t> reply_bytes {0x04, 0x05, 0x06};

    auto uut = std::make_shared<ProtocolMessageHandlerImpl>(tcp_sender_, tcp_server_, serializer_);

    ON_CALL(*serializer_, serialize(A<const PushMessage &>())).WillByDefault(Return(request_bytes));
    ON_CALL(*serializer_, deserialize(_, _))
        .WillByDefault(
            [&](const std::vector<uint8_t> &, MessageDeserializationResultReceptor &receptor) {
                receptor.deserialized(reply);
            });
    ON_CALL(*tcp_sender_, send(_, _, _)).WillByDefault(Return(true));

    auto future = uut->send(p1, request);
    EXPECT_TRUE(future.valid());

    std::thread reply_thread {
        [&] { uut->on_message_received(p1, reply_bytes.data(), reply_bytes.size()); }};

    auto future_status = future.wait_for(std::chrono::milliseconds {100});
    EXPECT_EQ(future_status, std::future_status::timeout);

    reply_thread.join();
}

TEST_F(ProtocolMessageHandlerTest, SendAndReceiveReply_AddressMismatch)
{
    Random rng;

    IPv4Address p1 = conversion::to_ipv4_address("192.168.0.1");
    IPv4Address p2 = conversion::to_ipv4_address("192.168.0.2");

    PushMessage request;
    request.request_id = rng.next<RequestId>();

    BasicReply reply {request.message_code};
    reply.request_id  = request.request_id;
    reply.status_code = StatusCode::OK;

    std::vector<std::uint8_t> request_bytes {0x01, 0x02, 0x03};
    std::vector<std::uint8_t> reply_bytes {0x04, 0x05, 0x06};

    auto uut = std::make_shared<ProtocolMessageHandlerImpl>(tcp_sender_, tcp_server_, serializer_);

    ON_CALL(*serializer_, serialize(A<const PushMessage &>())).WillByDefault(Return(request_bytes));
    ON_CALL(*serializer_, deserialize(_, _))
        .WillByDefault(
            [&](const std::vector<uint8_t> &, MessageDeserializationResultReceptor &receptor) {
                receptor.deserialized(reply);
            });
    ON_CALL(*tcp_sender_, send(_, _, _)).WillByDefault(Return(true));

    auto future = uut->send(p1, request);
    EXPECT_TRUE(future.valid());

    std::thread reply_thread {
        [&] { uut->on_message_received(p2, reply_bytes.data(), reply_bytes.size()); }};

    auto future_status = future.wait_for(std::chrono::milliseconds {100});
    EXPECT_EQ(future_status, std::future_status::timeout);

    reply_thread.join();
}

TEST_F(ProtocolMessageHandlerTest, SendAndReceiveReply_RequestMessageCodeMismatch)
{
    Random rng;

    IPv4Address p1 = conversion::to_ipv4_address("192.168.0.1");

    PushMessage request;
    request.request_id = rng.next<RequestId>();

    BasicReply reply {MessageCode::PING};
    reply.request_id  = request.request_id;
    reply.status_code = StatusCode::OK;

    std::vector<std::uint8_t> request_bytes {0x01, 0x02, 0x03};
    std::vector<std::uint8_t> reply_bytes {0x04, 0x05, 0x06};

    auto uut = std::make_shared<ProtocolMessageHandlerImpl>(tcp_sender_, tcp_server_, serializer_);

    ON_CALL(*serializer_, serialize(A<const PushMessage &>())).WillByDefault(Return(request_bytes));
    ON_CALL(*serializer_, deserialize(_, _))
        .WillByDefault(
            [&](const std::vector<uint8_t> &, MessageDeserializationResultReceptor &receptor) {
                receptor.deserialized(reply);
            });
    ON_CALL(*tcp_sender_, send(_, _, _)).WillByDefault(Return(true));

    auto future = uut->send(p1, request);
    EXPECT_TRUE(future.valid());

    std::thread reply_thread {
        [&] { uut->on_message_received(p1, reply_bytes.data(), reply_bytes.size()); }};

    auto future_status = future.wait_for(std::chrono::milliseconds {100});
    EXPECT_EQ(future_status, std::future_status::timeout);

    reply_thread.join();
}

TEST_F(ProtocolMessageHandlerTest, InboundRequest)
{
    Random rng;

    IPv4Address p1 = conversion::to_ipv4_address("192.168.0.1");

    PingMessage request;
    request.request_id = rng.next<RequestId>();
    std::vector<std::uint8_t> request_bytes {0x01, 0x02, 0x03};

    auto uut = std::make_shared<ProtocolMessageHandlerImpl>(tcp_sender_, tcp_server_, serializer_);
    uut->register_message_listener(listener_);

    EXPECT_CALL(*serializer_, deserialize(request_bytes, _))
        .Times(1)
        .WillOnce(
            [&](const std::vector<uint8_t> &, MessageDeserializationResultReceptor &receptor) {
                receptor.deserialized(request);
            });
    EXPECT_CALL(*listener_,
        on_message_received(p1,
            Matcher<const PingMessage &>(AllOf(Field(&PingMessage::request_id, request.request_id),
                Field(&PingMessage::message_code, request.message_code)))))
        .Times(1);

    uut->on_message_received(p1, request_bytes.data(), request_bytes.size());
}
