#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <future>
#include <memory>

#include "dnlconfig.hpp"
#include "dnlflowimpl.hpp"
#include "inboundrequestdispatcher.hpp"
#include "iothreadpool.hpp"
#include "random.hpp"
#include "testutils.hpp"
#include "threadpool.hpp"

#include "dnlconfigloader_mock.hpp"
#include "dnlflowlistener_mock.hpp"
#include "protocolmessagehandler_mock.hpp"

using namespace ::testing;
using namespace ::sand::flows;
using namespace ::sand::utils;
using namespace ::sand::network;
using namespace ::sand::protocol;

namespace
{
class DNLFlowTest : public Test
{
protected:
    void SetUp() override
    {
        protocol_message_handler_ = std::make_shared<NiceMock<ProtocolMessageHandlerMock>>();
        inbound_request_dispatcher_ =
            std::make_shared<InboundRequestDispatcher>(protocol_message_handler_);
        dnl_config_loader_ = new NiceMock<DNLConfigLoaderMock>;
        dnl_config_ =
            std::make_shared<DNLConfig>(std::unique_ptr<DNLConfigLoader>(dnl_config_loader_));
        thread_pool_ = std::make_shared<ThreadPool>();
        listener_    = std::make_shared<NiceMock<DNLFlowListenerMock>>();
    }

    std::unique_ptr<DNLFlow> make_dnl_flow(int sync_period_ms = 0)
    {
        return std::make_unique<DNLFlowImpl>(protocol_message_handler_, inbound_request_dispatcher_,
            dnl_config_, thread_pool_, thread_pool_, sync_period_ms);
    }

    std::shared_ptr<ProtocolMessageHandlerMock> protocol_message_handler_;
    std::shared_ptr<InboundRequestDispatcher>   inbound_request_dispatcher_;
    DNLConfigLoaderMock *                       dnl_config_loader_;
    std::shared_ptr<DNLConfig>                  dnl_config_;
    std::shared_ptr<Executer>                   thread_pool_;
    std::shared_ptr<DNLFlowListenerMock>        listener_;
    Random                                      rng_;
};
}  // namespace

TEST_F(DNLFlowTest, States)
{
    auto flow = make_dnl_flow();

    EXPECT_EQ(flow->state(), DNLFlow::State::IDLE);
    flow->start();
    EXPECT_EQ(flow->state(), DNLFlow::State::RUNNING);
    flow->stop();
    EXPECT_EQ(flow->state(), DNLFlow::State::IDLE);
}

TEST_F(DNLFlowTest, HandlePing)
{
    const auto sleep_duration = std::chrono::milliseconds(50);
    const auto peer1          = testutils::random_ip_address(rng_);

    auto flow = make_dnl_flow();
    flow->start();

    PingMessage msg;
    msg.request_id = rng_.next<RequestId>();
    EXPECT_CALL(*protocol_message_handler_,
        send_reply(peer1, AllOf(Pointee(Field(&BasicReply::request_id, msg.request_id)),
                              Pointee(Field(&BasicReply::request_message_code, msg.message_code)),
                              Pointee(Field(&BasicReply::status_code, StatusCode::OK)))))
        .Times(1)
        .WillOnce([](...) { return std::async(std::launch::deferred, [] { return true; }); });
    inbound_request_dispatcher_->on_message_received(peer1, msg);

    thread_pool_->process_all_jobs();
}

TEST_F(DNLFlowTest, HandlePing_FlowNotRunning)
{
    const auto sleep_duration = std::chrono::milliseconds(50);
    const auto peer1          = testutils::random_ip_address(rng_);

    auto flow = make_dnl_flow();

    PingMessage msg;
    msg.request_id = rng_.next<RequestId>();
    EXPECT_CALL(*protocol_message_handler_, send_reply(peer1, _)).Times(0);
    inbound_request_dispatcher_->on_message_received(peer1, msg);

    thread_pool_->process_all_jobs();
}

TEST_F(DNLFlowTest, HandlePush)
{
    const auto sleep_duration = std::chrono::milliseconds(50);
    const auto peer1          = testutils::random_ip_address(rng_);
    const auto peer2          = testutils::random_ip_address(rng_);

    auto flow = make_dnl_flow();
    flow->start();
    flow->register_listener(listener_);

    PushMessage push;
    push.request_id = rng_.next<RequestId>();

    EXPECT_CALL(*listener_, on_node_connected(peer1)).Times(1);
    EXPECT_CALL(*protocol_message_handler_,
        send_reply(peer1, AllOf(Pointee(Field(&BasicReply::request_id, push.request_id)),
                              Pointee(Field(&BasicReply::request_message_code, push.message_code)),
                              Pointee(Field(&BasicReply::status_code, StatusCode::OK)))))
        .Times(1)
        .WillOnce([](...) { return std::async(std::launch::deferred, [] { return true; }); });

    inbound_request_dispatcher_->on_message_received(peer1, push);

    thread_pool_->process_all_jobs();
    EXPECT_TRUE(Mock::VerifyAndClearExpectations(protocol_message_handler_.get()));
    EXPECT_TRUE(Mock::VerifyAndClearExpectations(listener_.get()));

    PullMessage pull;
    pull.request_id    = rng_.next<RequestId>();
    pull.address_count = 1;

    EXPECT_CALL(*protocol_message_handler_,
        send(peer1, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PING))))
        .Times(1)
        .WillOnce(testutils::make_basic_reply_generator(true));
    EXPECT_CALL(*protocol_message_handler_,
        send_reply(peer2, AllOf(Pointee(Field(&BasicReply::request_id, pull.request_id)),
                              Pointee(Field(&BasicReply::status_code, StatusCode::OK)),
                              Pointee(Field(&BasicReply::request_message_code, pull.message_code)),
                              ResultOf([](auto &&ptr) { return ptr.get(); },
                                  WhenDynamicCastTo<PullReply *>(
                                      Pointee(Field(&PullReply::peers, ElementsAre(peer1))))))))
        .Times(1)
        .WillOnce([](...) { return std::async(std::launch::deferred, [] { return true; }); });

    inbound_request_dispatcher_->on_message_received(peer2, pull);

    thread_pool_->process_all_jobs();
}

TEST_F(DNLFlowTest, HandlePush_NotNotifiedASecondTime)
{
    const auto sleep_duration = std::chrono::milliseconds(50);
    const auto peer1          = testutils::random_ip_address(rng_);

    auto flow = make_dnl_flow();
    flow->start();
    flow->register_listener(listener_);

    PushMessage push;
    push.request_id = rng_.next<RequestId>();

    EXPECT_CALL(*listener_, on_node_connected(peer1)).Times(1);
    EXPECT_CALL(*protocol_message_handler_,
        send_reply(peer1, AllOf(Pointee(Field(&BasicReply::request_id, push.request_id)),
                              Pointee(Field(&BasicReply::request_message_code, push.message_code)),
                              Pointee(Field(&BasicReply::status_code, StatusCode::OK)))))
        .Times(1)
        .WillOnce([](...) { return std::async(std::launch::deferred, [] { return true; }); });

    inbound_request_dispatcher_->on_message_received(peer1, push);

    thread_pool_->process_all_jobs();
    EXPECT_TRUE(Mock::VerifyAndClearExpectations(protocol_message_handler_.get()));

    EXPECT_CALL(*protocol_message_handler_,
        send_reply(peer1, AllOf(Pointee(Field(&BasicReply::request_id, push.request_id)),
                              Pointee(Field(&BasicReply::request_message_code, push.message_code)),
                              Pointee(Field(&BasicReply::status_code, StatusCode::DUPLICATION)))))
        .Times(1)
        .WillOnce([](...) { return std::async(std::launch::deferred, [] { return true; }); });

    inbound_request_dispatcher_->on_message_received(peer1, push);

    thread_pool_->process_all_jobs();
}

TEST_F(DNLFlowTest, HandleBye)
{
    const auto sleep_duration = std::chrono::milliseconds(50);
    const auto peer1          = testutils::random_ip_address(rng_);
    const auto peer2          = testutils::random_ip_address(rng_);

    auto flow = make_dnl_flow();
    flow->start();
    flow->register_listener(listener_);

    PushMessage push;
    push.request_id = rng_.next<RequestId>();

    EXPECT_CALL(*listener_, on_node_connected(peer1)).Times(1);
    EXPECT_CALL(*protocol_message_handler_,
        send_reply(peer1, AllOf(Pointee(Field(&BasicReply::request_id, push.request_id)),
                              Pointee(Field(&BasicReply::request_message_code, push.message_code)),
                              Pointee(Field(&BasicReply::status_code, StatusCode::OK)))))
        .Times(1)
        .WillOnce([](...) { return std::async(std::launch::deferred, [] { return true; }); });

    inbound_request_dispatcher_->on_message_received(peer1, push);

    thread_pool_->process_all_jobs();
    EXPECT_TRUE(Mock::VerifyAndClearExpectations(protocol_message_handler_.get()));
    EXPECT_TRUE(Mock::VerifyAndClearExpectations(listener_.get()));

    ByeMessage bye;
    bye.request_id = rng_.next<RequestId>();

    EXPECT_CALL(*listener_, on_node_disconnected(peer1)).Times(1);

    inbound_request_dispatcher_->on_message_received(peer1, bye);

    thread_pool_->process_all_jobs();
    EXPECT_TRUE(Mock::VerifyAndClearExpectations(listener_.get()));

    PullMessage pull;
    pull.request_id    = rng_.next<RequestId>();
    pull.address_count = 1;

    EXPECT_CALL(*protocol_message_handler_,
        send(peer1, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PING))))
        .Times(0);
    EXPECT_CALL(*protocol_message_handler_,
        send_reply(peer2,
            AllOf(Pointee(Field(&BasicReply::request_id, pull.request_id)),
                Pointee(Field(&BasicReply::status_code, StatusCode::RESOURCE_NOT_AVAILABLE)),
                Pointee(Field(&BasicReply::request_message_code, pull.message_code)),
                ResultOf([](auto &&ptr) { return ptr.get(); },
                    WhenDynamicCastTo<PullReply *>(Pointee(Field(&PullReply::peers, IsEmpty())))))))
        .Times(1)
        .WillOnce([](...) { return std::async(std::launch::deferred, [] { return true; }); });

    inbound_request_dispatcher_->on_message_received(peer2, pull);

    thread_pool_->process_all_jobs();
}

TEST_F(DNLFlowTest, HandlePull_LessThanAvailable)
{
    const size_t             total_peers     = 10;
    const size_t             requested_peers = 5;
    const auto               sleep_duration  = std::chrono::milliseconds(50);
    const auto               pull_msg_peer   = testutils::random_ip_address(rng_);
    std::vector<IPv4Address> push_msg_peers(total_peers);
    std::generate(push_msg_peers.begin(), push_msg_peers.end(),
        [&] { return testutils::random_ip_address(rng_); });

    auto flow = make_dnl_flow();
    flow->start();

    std::vector<PushMessage> push_messages(total_peers);
    for (size_t i = 0; i != total_peers; ++i)
    {
        push_messages[i].request_id = rng_.next<RequestId>();
        EXPECT_CALL(*protocol_message_handler_,
            send_reply(push_msg_peers[i],
                AllOf(Pointee(Field(&BasicReply::request_id, push_messages[i].request_id)),
                    Pointee(
                        Field(&BasicReply::request_message_code, push_messages[i].message_code)),
                    Pointee(Field(&BasicReply::status_code, StatusCode::OK)))))
            .Times(1)
            .WillOnce([](...) { return std::async(std::launch::deferred, [] { return true; }); });
        inbound_request_dispatcher_->on_message_received(push_msg_peers[i], push_messages[i]);
        thread_pool_->process_all_jobs();
    }

    EXPECT_TRUE(Mock::VerifyAndClearExpectations(protocol_message_handler_.get()));

    PullMessage pull;
    pull.request_id    = rng_.next<RequestId>();
    pull.address_count = uint8_t(requested_peers);

    for (size_t i = 0; i != total_peers; ++i)
    {
        EXPECT_CALL(*protocol_message_handler_,
            send(push_msg_peers[i],
                Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PING))))
            .Times(AtMost(1))
            .WillOnce(testutils::make_basic_reply_generator(true));
    }

    EXPECT_CALL(*protocol_message_handler_,
        send_reply(pull_msg_peer,
            AllOf(Pointee(Field(&BasicReply::request_id, pull.request_id)),
                Pointee(Field(&BasicReply::status_code, StatusCode::OK)),
                Pointee(Field(&BasicReply::request_message_code, pull.message_code)),
                ResultOf([](auto &&ptr) { return ptr.get(); },
                    WhenDynamicCastTo<PullReply *>(Pointee(Field(&PullReply::peers,
                        AllOf(SizeIs(requested_peers), IsSubsetOf(push_msg_peers)))))))))
        .Times(1)
        .WillOnce([](...) { return std::async(std::launch::deferred, [] { return true; }); });

    inbound_request_dispatcher_->on_message_received(pull_msg_peer, pull);

    thread_pool_->process_all_jobs();
}

TEST_F(DNLFlowTest, HandlePull_MoreThanAvailable)
{
    const size_t             total_peers     = 10;
    const size_t             requested_peers = 15;
    const auto               sleep_duration  = std::chrono::milliseconds(50);
    const auto               pull_msg_peer   = testutils::random_ip_address(rng_);
    std::vector<IPv4Address> push_msg_peers(total_peers);
    std::generate(push_msg_peers.begin(), push_msg_peers.end(),
        [&] { return testutils::random_ip_address(rng_); });

    auto flow = make_dnl_flow();
    flow->start();

    std::vector<PushMessage> push_messages(total_peers);
    for (size_t i = 0; i != total_peers; ++i)
    {
        push_messages[i].request_id = rng_.next<RequestId>();
        EXPECT_CALL(*protocol_message_handler_,
            send_reply(push_msg_peers[i],
                AllOf(Pointee(Field(&BasicReply::request_id, push_messages[i].request_id)),
                    Pointee(
                        Field(&BasicReply::request_message_code, push_messages[i].message_code)),
                    Pointee(Field(&BasicReply::status_code, StatusCode::OK)))))
            .Times(1)
            .WillOnce([](...) { return std::async(std::launch::deferred, [] { return true; }); });
        inbound_request_dispatcher_->on_message_received(push_msg_peers[i], push_messages[i]);
        thread_pool_->process_all_jobs();
    }

    EXPECT_TRUE(Mock::VerifyAndClearExpectations(protocol_message_handler_.get()));

    PullMessage pull;
    pull.request_id    = rng_.next<RequestId>();
    pull.address_count = uint8_t(requested_peers);

    for (size_t i = 0; i != total_peers; ++i)
    {
        EXPECT_CALL(*protocol_message_handler_,
            send(push_msg_peers[i],
                Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PING))))
            .Times(1)
            .WillOnce(testutils::make_basic_reply_generator(true));
    }

    EXPECT_CALL(*protocol_message_handler_,
        send_reply(pull_msg_peer,
            AllOf(Pointee(Field(&BasicReply::request_id, pull.request_id)),
                Pointee(Field(&BasicReply::status_code, StatusCode::OK)),
                Pointee(Field(&BasicReply::request_message_code, pull.message_code)),
                ResultOf([](auto &&ptr) { return ptr.get(); },
                    WhenDynamicCastTo<PullReply *>(Pointee(Field(&PullReply::peers,
                        AllOf(SizeIs(total_peers), UnorderedElementsAreArray(push_msg_peers)))))))))
        .Times(1)
        .WillOnce([](...) { return std::async(std::launch::deferred, [] { return true; }); });

    inbound_request_dispatcher_->on_message_received(pull_msg_peer, pull);

    thread_pool_->process_all_jobs();
}

TEST_F(DNLFlowTest, DNLSync_ForeignDNLSyncMessageSource)
{
    using namespace std::chrono;

    const auto   sleep_duration         = std::chrono::milliseconds(50);
    const size_t initial_peer_count     = 3;
    const size_t num_of_peers_to_remove = 1;
    const size_t num_of_peers_to_add    = 2;
    const auto   other_dnl_addr         = testutils::random_ip_address(rng_);
    const auto   pull_src_addr          = testutils::random_ip_address(rng_);

    std::vector<IPv4Address> initial_peers(initial_peer_count);
    std::generate(initial_peers.begin(), initial_peers.end(),
        [&] { return testutils::random_ip_address(rng_); });

    std::vector<IPv4Address> new_peers(num_of_peers_to_add);
    std::generate(
        new_peers.begin(), new_peers.end(), [&] { return testutils::random_ip_address(rng_); });

    ON_CALL(*dnl_config_loader_, load()).WillByDefault(Return(std::vector<IPv4Address> {}));
    dnl_config_->reload();

    auto flow = make_dnl_flow();
    flow->start();

    std::vector<PushMessage> push_messages(initial_peer_count);
    for (size_t i = 0; i != initial_peer_count; ++i)
    {
        push_messages[i].request_id = rng_.next<RequestId>();
        EXPECT_CALL(*protocol_message_handler_,
            send_reply(initial_peers[i],
                AllOf(Pointee(Field(&BasicReply::request_id, push_messages[i].request_id)),
                    Pointee(
                        Field(&BasicReply::request_message_code, push_messages[i].message_code)),
                    Pointee(Field(&BasicReply::status_code, StatusCode::OK)))))
            .Times(1)
            .WillOnce([](...) { return std::async(std::launch::deferred, [] { return true; }); });
        inbound_request_dispatcher_->on_message_received(initial_peers[i], push_messages[i]);
        thread_pool_->process_all_jobs();
    }

    EXPECT_TRUE(Mock::VerifyAndClearExpectations(protocol_message_handler_.get()));

    flow->register_listener(listener_);

    DNLSyncMessage sync;
    sync.request_id = rng_.next<RequestId>();
    for (const auto &peer : new_peers)
    {
        sync.entries.push_back({system_clock::now(), peer, DNLSyncMessage::Entry::ADD_ADDRESS});
        EXPECT_CALL(*listener_, on_node_connected(peer)).Times(0);
    }
    for (size_t i = 0; i != num_of_peers_to_remove; ++i)
    {
        sync.entries.push_back(
            {system_clock::now(), initial_peers[i], DNLSyncMessage::Entry::REMOVE_ADDRESS});
    }
    for (size_t i = 0; i != initial_peers.size(); ++i)
    {
        EXPECT_CALL(*listener_, on_node_disconnected(initial_peers[i])).Times(0);
    }

    EXPECT_CALL(*protocol_message_handler_,
        send_reply(other_dnl_addr,
            AllOf(Pointee(Field(&BasicReply::request_id, sync.request_id)),
                Pointee(Field(&BasicReply::request_message_code, sync.message_code)),
                Pointee(Field(&BasicReply::status_code, StatusCode::FOREIGN_DNL_ADDRESS)))))
        .Times(1)
        .WillOnce([](...) { return std::async(std::launch::deferred, [] { return true; }); });

    inbound_request_dispatcher_->on_message_received(other_dnl_addr, sync);

    thread_pool_->process_all_jobs();
    EXPECT_TRUE(Mock::VerifyAndClearExpectations(protocol_message_handler_.get()));

    PullMessage pull;
    pull.request_id    = rng_.next<RequestId>();
    pull.address_count = uint8_t(initial_peer_count + num_of_peers_to_add - num_of_peers_to_remove);

    for (auto &peer : initial_peers)
    {
        EXPECT_CALL(*protocol_message_handler_,
            send(peer, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PING))))
            .Times(1)
            .WillOnce(testutils::make_basic_reply_generator(true));
    }

    for (auto &peer : new_peers)
    {
        EXPECT_CALL(*protocol_message_handler_,
            send(peer, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PING))))
            .Times(0);
    }

    EXPECT_CALL(*protocol_message_handler_,
        send_reply(pull_src_addr,
            AllOf(Pointee(Field(&BasicReply::request_id, pull.request_id)),
                Pointee(Field(&BasicReply::status_code, StatusCode::OK)),
                Pointee(Field(&BasicReply::request_message_code, pull.message_code)),
                ResultOf([](auto &&ptr) { return ptr.get(); },
                    WhenDynamicCastTo<PullReply *>(Pointee(
                        Field(&PullReply::peers, UnorderedElementsAreArray(initial_peers))))))))
        .Times(1)
        .WillOnce([](...) { return std::async(std::launch::deferred, [] { return true; }); });

    inbound_request_dispatcher_->on_message_received(pull_src_addr, pull);

    thread_pool_->process_all_jobs();
}

TEST_F(DNLFlowTest, DNLSync_LocalSyncTimerDisabled)
{
    using namespace std::chrono;

    const auto   sleep_duration         = std::chrono::milliseconds(50);
    const size_t initial_peer_count     = 3;
    const size_t num_of_peers_to_remove = 1;
    const size_t num_of_peers_to_add    = 2;
    const auto   other_dnl_addr         = testutils::random_ip_address(rng_);
    const auto   pull_src_addr          = testutils::random_ip_address(rng_);

    std::vector<IPv4Address> initial_peers(initial_peer_count);
    std::generate(initial_peers.begin(), initial_peers.end(),
        [&] { return testutils::random_ip_address(rng_); });

    std::vector<IPv4Address> new_peers(num_of_peers_to_add);
    std::generate(
        new_peers.begin(), new_peers.end(), [&] { return testutils::random_ip_address(rng_); });

    ON_CALL(*dnl_config_loader_, load())
        .WillByDefault(Return(std::vector<IPv4Address> {other_dnl_addr}));
    dnl_config_->reload();

    auto flow = make_dnl_flow();
    flow->start();

    std::vector<PushMessage> push_messages(initial_peer_count);
    for (size_t i = 0; i != initial_peer_count; ++i)
    {
        push_messages[i].request_id = rng_.next<RequestId>();
        EXPECT_CALL(*protocol_message_handler_,
            send_reply(initial_peers[i],
                AllOf(Pointee(Field(&BasicReply::request_id, push_messages[i].request_id)),
                    Pointee(
                        Field(&BasicReply::request_message_code, push_messages[i].message_code)),
                    Pointee(Field(&BasicReply::status_code, StatusCode::OK)))))
            .Times(1)
            .WillOnce([](...) { return std::async(std::launch::deferred, [] { return true; }); });
        inbound_request_dispatcher_->on_message_received(initial_peers[i], push_messages[i]);
        thread_pool_->process_all_jobs();
    }

    EXPECT_TRUE(Mock::VerifyAndClearExpectations(protocol_message_handler_.get()));

    flow->register_listener(listener_);

    DNLSyncMessage sync;
    sync.request_id = rng_.next<RequestId>();
    for (const auto &peer : new_peers)
    {
        sync.entries.push_back({system_clock::now(), peer, DNLSyncMessage::Entry::ADD_ADDRESS});
        EXPECT_CALL(*listener_, on_node_connected(peer)).Times(1);
    }
    for (size_t i = 0; i != num_of_peers_to_remove; ++i)
    {
        sync.entries.push_back(
            {system_clock::now(), initial_peers[i], DNLSyncMessage::Entry::REMOVE_ADDRESS});
        EXPECT_CALL(*listener_, on_node_disconnected(initial_peers[i])).Times(1);
    }
    for (size_t i = num_of_peers_to_remove; i != initial_peers.size(); ++i)
    {
        EXPECT_CALL(*listener_, on_node_disconnected(initial_peers[i])).Times(0);
    }

    EXPECT_CALL(*protocol_message_handler_,
        send_reply(other_dnl_addr,
            AllOf(Pointee(Field(&BasicReply::request_id, sync.request_id)),
                Pointee(Field(&BasicReply::request_message_code, sync.message_code)),
                Pointee(Field(&BasicReply::status_code, StatusCode::OK)))))
        .Times(1)
        .WillOnce([](...) { return std::async(std::launch::deferred, [] { return true; }); });

    inbound_request_dispatcher_->on_message_received(other_dnl_addr, sync);

    thread_pool_->process_all_jobs();
    EXPECT_TRUE(Mock::VerifyAndClearExpectations(protocol_message_handler_.get()));

    PullMessage pull;
    pull.request_id    = rng_.next<RequestId>();
    pull.address_count = uint8_t(initial_peer_count + num_of_peers_to_add - num_of_peers_to_remove);

    std::vector<IPv4Address> remaining_initial_peers;
    for (size_t i = 0; i != initial_peers.size(); ++i)
    {
        if (i < num_of_peers_to_remove)
        {
            EXPECT_CALL(*protocol_message_handler_,
                send(initial_peers[i],
                    Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PING))))
                .Times(0);
        }
        else
        {
            EXPECT_CALL(*protocol_message_handler_,
                send(initial_peers[i],
                    Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PING))))
                .Times(1)
                .WillOnce(testutils::make_basic_reply_generator(true));
            remaining_initial_peers.push_back(initial_peers[i]);
        }
    }

    for (auto &peer : new_peers)
    {
        EXPECT_CALL(*protocol_message_handler_,
            send(peer, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PING))))
            .Times(1)
            .WillOnce(testutils::make_basic_reply_generator(true));
    }

    EXPECT_CALL(*protocol_message_handler_,
        send_reply(
            pull_src_addr, AllOf(Pointee(Field(&BasicReply::request_id, pull.request_id)),
                               Pointee(Field(&BasicReply::status_code, StatusCode::OK)),
                               Pointee(Field(&BasicReply::request_message_code, pull.message_code)),
                               ResultOf([](auto &&ptr) { return ptr.get(); },
                                   WhenDynamicCastTo<PullReply *>(Pointee(Field(&PullReply::peers,
                                       AllOf(SizeIs(pull.address_count), IsSupersetOf(new_peers),
                                           IsSupersetOf(remaining_initial_peers)))))))))
        .Times(1)
        .WillOnce([](...) { return std::async(std::launch::deferred, [] { return true; }); });

    inbound_request_dispatcher_->on_message_received(pull_src_addr, pull);

    thread_pool_->process_all_jobs();
}

MATCHER(DNLSyncEntryEq_NoTS, "Equality comparison for DNLSync::Entry, timestamp ignored")
{
    return std::get<0>(arg).address == std::get<1>(arg).address &&
           std::get<0>(arg).action == std::get<1>(arg).action;
}

TEST_F(DNLFlowTest, DNLSync_SendMessage)
{
    using namespace std::chrono;

    const auto   sleep_duration = std::chrono::milliseconds(50);
    const auto   timer_interval = std::chrono::milliseconds(250);
    const size_t peer_count     = 3;
    const auto   other_dnl_addr = testutils::random_ip_address(rng_);

    std::vector<IPv4Address> peers(peer_count);
    std::generate(peers.begin(), peers.end(), [&] { return testutils::random_ip_address(rng_); });

    ON_CALL(*dnl_config_loader_, load())
        .WillByDefault(Return(std::vector<IPv4Address> {other_dnl_addr}));
    dnl_config_->reload();

    auto flow = make_dnl_flow(int(timer_interval.count()));
    flow->start();

    std::vector<PushMessage> push_messages(peer_count);
    for (size_t i = 0; i != peer_count; ++i)
    {
        push_messages[i].request_id = rng_.next<RequestId>();
        EXPECT_CALL(*protocol_message_handler_,
            send_reply(peers[i],
                AllOf(Pointee(Field(&BasicReply::request_id, push_messages[i].request_id)),
                    Pointee(
                        Field(&BasicReply::request_message_code, push_messages[i].message_code)),
                    Pointee(Field(&BasicReply::status_code, StatusCode::OK)))))
            .Times(1)
            .WillOnce([](...) { return std::async(std::launch::deferred, [] { return true; }); });
        inbound_request_dispatcher_->on_message_received(peers[i], push_messages[i]);
        std::this_thread::sleep_for(sleep_duration);
    }

    EXPECT_TRUE(Mock::VerifyAndClearExpectations(protocol_message_handler_.get()));

    std::vector<DNLSyncMessage::Entry> entries;
    entries.reserve(peers.size());
    for (const auto &peer : peers)
    {
        entries.push_back({{}, peer, DNLSyncMessage::Entry::ADD_ADDRESS});
    }

    EXPECT_CALL(*protocol_message_handler_,
        send(other_dnl_addr,
            AllOf(Pointee(Field(&sand::protocol::Message::message_code, MessageCode::DNLSYNC)),
                ResultOf([](auto &&ptr) { return ptr.get(); },
                    WhenDynamicCastTo<DNLSyncMessage *>(Pointee(Field(
                        &DNLSyncMessage::entries, Pointwise(DNLSyncEntryEq_NoTS(), entries))))))))
        .Times(1)
        .WillOnce(testutils::make_basic_reply_generator(true));

    std::this_thread::sleep_for(timer_interval);
}

TEST_F(DNLFlowTest, DNLSync_SendMessage_MergeLocalAndRemoteEventLists)
{
    using namespace std::chrono;

    const auto   sleep_duration         = std::chrono::milliseconds(50);
    const auto   timer_interval         = std::chrono::milliseconds(250);
    const size_t initial_peer_count     = 3;
    const size_t num_of_peers_to_remove = 1;
    const size_t num_of_peers_to_add    = 2;
    const auto   other_dnl_addr         = testutils::random_ip_address(rng_);

    std::vector<IPv4Address> initial_peers(initial_peer_count);
    std::generate(initial_peers.begin(), initial_peers.end(),
        [&] { return testutils::random_ip_address(rng_); });

    std::vector<IPv4Address> new_peers(num_of_peers_to_add);
    std::generate(
        new_peers.begin(), new_peers.end(), [&] { return testutils::random_ip_address(rng_); });

    ON_CALL(*dnl_config_loader_, load())
        .WillByDefault(Return(std::vector<IPv4Address> {other_dnl_addr}));
    dnl_config_->reload();

    auto flow = make_dnl_flow(int(timer_interval.count()));
    flow->start();

    std::vector<PushMessage> push_messages(initial_peer_count);
    for (size_t i = 0; i != initial_peer_count; ++i)
    {
        push_messages[i].request_id = rng_.next<RequestId>();
        EXPECT_CALL(*protocol_message_handler_,
            send_reply(initial_peers[i],
                AllOf(Pointee(Field(&BasicReply::request_id, push_messages[i].request_id)),
                    Pointee(
                        Field(&BasicReply::request_message_code, push_messages[i].message_code)),
                    Pointee(Field(&BasicReply::status_code, StatusCode::OK)))))
            .Times(1)
            .WillOnce([](...) { return std::async(std::launch::deferred, [] { return true; }); });
        inbound_request_dispatcher_->on_message_received(initial_peers[i], push_messages[i]);
        std::this_thread::sleep_for(sleep_duration);
    }

    EXPECT_TRUE(Mock::VerifyAndClearExpectations(protocol_message_handler_.get()));

    DNLSyncMessage sync;
    sync.request_id = rng_.next<RequestId>();
    for (const auto &peer : new_peers)
    {
        sync.entries.push_back({system_clock::now(), peer, DNLSyncMessage::Entry::ADD_ADDRESS});
    }
    for (size_t i = 0; i != num_of_peers_to_remove; ++i)
    {
        sync.entries.push_back(
            {system_clock::now(), initial_peers[i], DNLSyncMessage::Entry::REMOVE_ADDRESS});
    }

    EXPECT_CALL(*protocol_message_handler_,
        send_reply(other_dnl_addr,
            AllOf(Pointee(Field(&BasicReply::request_id, sync.request_id)),
                Pointee(Field(&BasicReply::request_message_code, sync.message_code)),
                Pointee(Field(&BasicReply::status_code, StatusCode::OK)))))
        .Times(1)
        .WillOnce([](...) { return std::async(std::launch::deferred, [] { return true; }); });

    inbound_request_dispatcher_->on_message_received(other_dnl_addr, sync);

    std::this_thread::sleep_for(sleep_duration);
    EXPECT_TRUE(Mock::VerifyAndClearExpectations(protocol_message_handler_.get()));

    PullMessage pull;
    pull.request_id    = rng_.next<RequestId>();
    pull.address_count = uint8_t(initial_peer_count + num_of_peers_to_add - num_of_peers_to_remove);

    std::vector<DNLSyncMessage::Entry> expected_entries;
    for (size_t i = 0; i != num_of_peers_to_remove; ++i)
    {
        expected_entries.push_back({{}, initial_peers[i], DNLSyncMessage::Entry::REMOVE_ADDRESS});
    }
    for (size_t i = num_of_peers_to_remove; i != initial_peers.size(); ++i)
    {
        expected_entries.push_back({{}, initial_peers[i], DNLSyncMessage::Entry::ADD_ADDRESS});
    }
    for (const auto &peer : new_peers)
    {
        expected_entries.push_back({{}, peer, DNLSyncMessage::Entry::ADD_ADDRESS});
    }

    EXPECT_CALL(*protocol_message_handler_,
        send(other_dnl_addr,
            AllOf(Pointee(Field(&sand::protocol::Message::message_code, MessageCode::DNLSYNC)),
                ResultOf([](auto &&ptr) { return ptr.get(); },
                    WhenDynamicCastTo<DNLSyncMessage *>(Pointee(Field(&DNLSyncMessage::entries,
                        UnorderedPointwise(DNLSyncEntryEq_NoTS(), expected_entries))))))))
        .Times(1)
        .WillOnce(testutils::make_basic_reply_generator(true));

    std::this_thread::sleep_for(timer_interval);
}
