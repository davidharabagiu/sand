#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <future>
#include <memory>

#include "dnlconfig.hpp"
#include "inboundrequestdispatcher.hpp"
#include "iothreadpool.hpp"
#include "peermanagerflowimpl.hpp"
#include "random.hpp"
#include "testutils.hpp"
#include "threadpool.hpp"

#include "dnlconfigloader_mock.hpp"
#include "peermanagerflowlistener_mock.hpp"
#include "protocolmessagehandler_mock.hpp"

using namespace ::testing;
using namespace ::sand::flows;
using namespace ::sand::protocol;
using namespace ::sand::network;
using namespace ::sand::utils;

namespace
{
class PeerManagerFlowTest : public Test
{
protected:
    void SetUp() override
    {
        protocol_message_handler_ = std::make_shared<NiceMock<ProtocolMessageHandlerMock>>();
        inbound_request_dispatcher_ =
            std::make_shared<InboundRequestDispatcher>(protocol_message_handler_);
        dnl_config_loader_ = new NiceMock<DNLConfigLoaderMock>();
        dnl_config_ =
            std::make_shared<DNLConfig>(std::unique_ptr<DNLConfigLoader>(dnl_config_loader_));
        executer_    = std::make_shared<ThreadPool>();
        io_executer_ = std::make_shared<IOThreadPool>();
        listener_    = std::make_shared<NiceMock<PeerManagerFlowListenerMock>>();
    }

    std::unique_ptr<PeerManagerFlowImpl> make_peer_manager()
    {
        auto flow = std::make_unique<PeerManagerFlowImpl>(protocol_message_handler_,
            inbound_request_dispatcher_, dnl_config_, executer_, io_executer_, 0);
        return flow;
    }

    IPv4Address random_ip_address()
    {
        return (rng_.next<IPv4Address>(255) << 24) | (rng_.next<IPv4Address>(255) << 16) |
               (rng_.next<IPv4Address>(255) << 8) | (rng_.next<IPv4Address>(255));
    }

    static auto make_pull_reply(const std::vector<IPv4Address> &payload)
    {
        return [=](auto, auto msg) {
            std::promise<std::unique_ptr<BasicReply>> promise;

            auto *_msg = dynamic_cast<PullMessage *>(msg.get());
            EXPECT_TRUE(_msg);
            EXPECT_EQ(_msg->message_code, MessageCode::PULL);

            auto reply         = std::make_unique<PullReply>();
            reply->peers       = payload;
            reply->request_id  = _msg->request_id;
            reply->status_code = payload.empty() ? StatusCode::UNREACHABLE : StatusCode::OK;
            promise.set_value(std::move(reply));

            return promise.get_future();
        };
    }

    static auto make_basic_reply(bool ok)
    {
        return [=](IPv4Address, std::unique_ptr<sand::protocol::Message> msg) {
            std::promise<std::unique_ptr<BasicReply>> promise;

            auto reply         = std::make_unique<BasicReply>(msg->message_code);
            reply->request_id  = msg->request_id;
            reply->status_code = ok ? StatusCode::OK : StatusCode::UNREACHABLE;
            promise.set_value(std::move(reply));

            return promise.get_future();
        };
    }

    std::shared_ptr<ProtocolMessageHandlerMock>  protocol_message_handler_;
    std::shared_ptr<InboundRequestDispatcher>    inbound_request_dispatcher_;
    DNLConfigLoaderMock *                        dnl_config_loader_;
    std::shared_ptr<DNLConfig>                   dnl_config_;
    std::shared_ptr<Executer>                    executer_;
    std::shared_ptr<Executer>                    io_executer_;
    std::shared_ptr<PeerManagerFlowListenerMock> listener_;
    std::chrono::milliseconds                    timeout_ {100};
    Random                                       rng_;
};
}  // namespace

TEST_F(PeerManagerFlowTest, GetPeers_FlowNotStarted)
{
    const size_t requested_peer_count = 1;
    const auto   dnla1                = random_ip_address();

    ON_CALL(*dnl_config_loader_, load()).WillByDefault(Return(std::vector<IPv4Address> {dnla1}));
    dnl_config_->reload();

    EXPECT_CALL(*protocol_message_handler_, send(AnyOf(dnla1), _)).Times(0);

    auto peer_manager = make_peer_manager();
    EXPECT_EQ(peer_manager->state(), PeerManagerFlow::State::IDLE);

    auto f = peer_manager->get_peers(requested_peer_count);
    EXPECT_EQ(f.wait_for(timeout_), std::future_status::ready);
    EXPECT_TRUE(f.get().empty());
}

TEST_F(PeerManagerFlowTest, GetPeers_DNLConfigEmpty)
{
    const size_t requested_peer_count = 3;

    ON_CALL(*dnl_config_loader_, load()).WillByDefault(Return(std::vector<IPv4Address> {}));
    dnl_config_->reload();

    auto peer_manager = make_peer_manager();
    peer_manager->start();
    EXPECT_TRUE(testutils::wait_for(
        [&] { return peer_manager->state() == PeerManagerFlow::State::ERROR; }, 100));

    auto f = peer_manager->get_peers(requested_peer_count);
    EXPECT_EQ(f.wait_for(timeout_), std::future_status::ready);
    EXPECT_TRUE(f.get().empty());
}

TEST_F(PeerManagerFlowTest, GetPeers_AllDNLNodesDown)
{
    const size_t requested_peer_count = 3;
    const auto   dnla1                = random_ip_address();

    ON_CALL(*dnl_config_loader_, load()).WillByDefault(Return(std::vector<IPv4Address> {dnla1}));
    dnl_config_->reload();

    EXPECT_CALL(*protocol_message_handler_,
        send(dnla1, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PULL))))
        .Times(0);
    EXPECT_CALL(*protocol_message_handler_,
        send(dnla1, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PUSH))))
        .Times(1)
        .WillOnce(make_basic_reply(false));

    auto peer_manager = make_peer_manager();
    peer_manager->start();
    EXPECT_TRUE(testutils::wait_for(
        [&] { return peer_manager->state() == PeerManagerFlow::State::ERROR; }, 100));

    auto f = peer_manager->get_peers(requested_peer_count);
    EXPECT_EQ(f.wait_for(timeout_), std::future_status::ready);
    EXPECT_TRUE(f.get().empty());
}

TEST_F(PeerManagerFlowTest, GetPeers_AllDNLNodesUp)
{
    const size_t requested_peer_count = 10;
    const auto   dnla1                = random_ip_address();
    const auto   dnla2                = random_ip_address();

    std::vector<IPv4Address> peers1(8);
    std::generate(peers1.begin(), peers1.end(), [&] { return random_ip_address(); });

    std::vector<IPv4Address> peers2(8);
    std::generate(peers2.begin(), peers2.end(), [&] { return random_ip_address(); });

    ON_CALL(*dnl_config_loader_, load())
        .WillByDefault(Return(std::vector<IPv4Address> {dnla1, dnla2}));
    dnl_config_->reload();

    ON_CALL(*protocol_message_handler_,
        send(dnla1, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PUSH))))
        .WillByDefault(make_basic_reply(true));
    ON_CALL(*protocol_message_handler_,
        send(dnla1, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PULL))))
        .WillByDefault(make_pull_reply(peers1));

    ON_CALL(*protocol_message_handler_,
        send(dnla2, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PUSH))))
        .WillByDefault(make_basic_reply(true));
    ON_CALL(*protocol_message_handler_,
        send(dnla2, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PULL))))
        .WillByDefault(make_pull_reply(peers2));

    for (auto peer : peers1)
    {
        ON_CALL(*protocol_message_handler_,
            send(peer, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PUSH))))
            .WillByDefault(make_basic_reply(true));
    }
    for (auto peer : peers2)
    {
        ON_CALL(*protocol_message_handler_,
            send(peer, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PUSH))))
            .WillByDefault(make_basic_reply(true));
    }

    auto peer_manager = make_peer_manager();
    peer_manager->start();
    EXPECT_TRUE(testutils::wait_for(
        [&] { return peer_manager->state() == PeerManagerFlow::State::RUNNING; }, 100));

    auto f = peer_manager->get_peers(requested_peer_count);
    EXPECT_EQ(f.wait_for(timeout_), std::future_status::ready);

    std::vector<IPv4Address> all_peers;
    all_peers.insert(all_peers.end(), peers1.cbegin(), peers1.cend());
    all_peers.insert(all_peers.end(), peers2.cbegin(), peers2.cend());

    auto got_peers = f.get();
    EXPECT_EQ(got_peers.size(), requested_peer_count);
    ASSERT_THAT(got_peers, IsSubsetOf(all_peers));
}

TEST_F(PeerManagerFlowTest, GetPeers_SomeDNLNodesDown)
{
    const size_t requested_peer_count = 10;
    const auto   dnla1                = random_ip_address();
    const auto   dnla2                = random_ip_address();

    std::vector<IPv4Address> peers(8);
    std::generate(peers.begin(), peers.end(), [&] { return random_ip_address(); });

    ON_CALL(*dnl_config_loader_, load())
        .WillByDefault(Return(std::vector<IPv4Address> {dnla1, dnla2}));
    dnl_config_->reload();

    ON_CALL(*protocol_message_handler_,
        send(dnla1, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PUSH))))
        .WillByDefault(make_basic_reply(false));
    ON_CALL(*protocol_message_handler_,
        send(dnla1, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PULL))))
        .WillByDefault(make_pull_reply({}));

    ON_CALL(*protocol_message_handler_,
        send(dnla2, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PUSH))))
        .WillByDefault(make_basic_reply(true));
    ON_CALL(*protocol_message_handler_,
        send(dnla2, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PULL))))
        .WillByDefault(make_pull_reply(peers));

    for (auto peer : peers)
    {
        ON_CALL(*protocol_message_handler_,
            send(peer, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PUSH))))
            .WillByDefault(make_basic_reply(true));
    }

    auto peer_manager = make_peer_manager();
    peer_manager->start();
    EXPECT_TRUE(testutils::wait_for(
        [&] { return peer_manager->state() == PeerManagerFlow::State::RUNNING; }, 100));

    auto f = peer_manager->get_peers(requested_peer_count);
    EXPECT_EQ(f.wait_for(timeout_), std::future_status::ready);
    ASSERT_THAT(f.get(), UnorderedElementsAreArray(peers));
}

TEST_F(PeerManagerFlowTest, GetPeers_AllDNLNodesUp_SomePeersDead)
{
    const size_t requested_peer_count = 10;
    const auto   dnla1                = random_ip_address();

    std::vector<IPv4Address> alive_peers(5);
    std::generate(alive_peers.begin(), alive_peers.end(), [&] { return random_ip_address(); });
    std::vector<IPv4Address> dead_peers(5);
    std::generate(alive_peers.begin(), alive_peers.end(), [&] { return random_ip_address(); });
    std::vector<IPv4Address> all_peers(alive_peers.cbegin(), alive_peers.cend());
    all_peers.insert(all_peers.end(), dead_peers.cbegin(), dead_peers.cend());

    ON_CALL(*dnl_config_loader_, load()).WillByDefault(Return(std::vector<IPv4Address> {dnla1}));
    dnl_config_->reload();

    ON_CALL(*protocol_message_handler_,
        send(dnla1, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PUSH))))
        .WillByDefault(make_basic_reply(true));
    ON_CALL(*protocol_message_handler_,
        send(dnla1, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PULL))))
        .WillByDefault(make_pull_reply(all_peers));

    for (auto peer : alive_peers)
    {
        ON_CALL(*protocol_message_handler_,
            send(peer, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PUSH))))
            .WillByDefault(make_basic_reply(true));
    }
    for (auto peer : dead_peers)
    {
        ON_CALL(*protocol_message_handler_,
            send(peer, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PUSH))))
            .WillByDefault(make_basic_reply(false));
    }

    auto peer_manager = make_peer_manager();
    peer_manager->start();
    EXPECT_TRUE(testutils::wait_for(
        [&] { return peer_manager->state() == PeerManagerFlow::State::RUNNING; }, 100));

    auto f = peer_manager->get_peers(requested_peer_count);
    EXPECT_EQ(f.wait_for(timeout_), std::future_status::ready);

    auto got_peers = f.get();
    ASSERT_THAT(got_peers, UnorderedElementsAreArray(alive_peers));
}

TEST_F(PeerManagerFlowTest, GetPeers_AllDNLNodesUp_SomePeersDead_UseSecondDNLAsBackup)
{
    const size_t requested_peer_count = 10;
    const auto   dnla1                = random_ip_address();
    const auto   dnla2                = random_ip_address();

    std::vector<IPv4Address> alive_peers(5);
    std::generate(alive_peers.begin(), alive_peers.end(), [&] { return random_ip_address(); });
    std::vector<IPv4Address> dead_peers(5);
    std::generate(alive_peers.begin(), alive_peers.end(), [&] { return random_ip_address(); });
    std::vector<IPv4Address> all_peers(alive_peers.cbegin(), alive_peers.cend());
    all_peers.insert(all_peers.end(), dead_peers.cbegin(), dead_peers.cend());
    std::vector<IPv4Address> dnln1_peers;
    std::copy_n(alive_peers.cbegin(), 3, std::back_inserter(dnln1_peers));
    std::copy_n(dead_peers.cbegin(), 2, std::back_inserter(dnln1_peers));
    std::vector<IPv4Address> dnln2_peers;
    std::copy_n(alive_peers.crbegin(), 2, std::back_inserter(dnln2_peers));
    std::copy_n(dead_peers.crbegin(), 3, std::back_inserter(dnln2_peers));

    ON_CALL(*dnl_config_loader_, load())
        .WillByDefault(Return(std::vector<IPv4Address> {dnla1, dnla2}));
    dnl_config_->reload();

    ON_CALL(*protocol_message_handler_,
        send(dnla1, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PUSH))))
        .WillByDefault(make_basic_reply(true));
    ON_CALL(*protocol_message_handler_,
        send(dnla1, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PULL))))
        .WillByDefault(make_pull_reply(dnln1_peers));

    ON_CALL(*protocol_message_handler_,
        send(dnla2, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PUSH))))
        .WillByDefault(make_basic_reply(true));
    ON_CALL(*protocol_message_handler_,
        send(dnla2, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PULL))))
        .WillByDefault(make_pull_reply(dnln2_peers));

    for (auto peer : alive_peers)
    {
        ON_CALL(*protocol_message_handler_,
            send(peer, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PUSH))))
            .WillByDefault(make_basic_reply(true));
    }
    for (auto peer : dead_peers)
    {
        ON_CALL(*protocol_message_handler_,
            send(peer, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PUSH))))
            .WillByDefault(make_basic_reply(false));
    }

    auto peer_manager = make_peer_manager();
    peer_manager->start();
    EXPECT_TRUE(testutils::wait_for(
        [&] { return peer_manager->state() == PeerManagerFlow::State::RUNNING; }, 100));

    auto f = peer_manager->get_peers(requested_peer_count);
    EXPECT_EQ(f.wait_for(timeout_), std::future_status::ready);

    auto got_peers = f.get();
    ASSERT_THAT(got_peers, UnorderedElementsAreArray(alive_peers));
}

TEST_F(PeerManagerFlowTest, GetPeers_FromOtherPeers_Cause_SomeDied)
{
    const size_t requested_peer_count = 10;
    const auto   dnla1                = random_ip_address();

    std::vector<IPv4Address> peers(10);
    std::generate(peers.begin(), peers.end(), [&] { return random_ip_address(); });

    ON_CALL(*dnl_config_loader_, load()).WillByDefault(Return(std::vector<IPv4Address> {dnla1}));
    dnl_config_->reload();

    ON_CALL(*protocol_message_handler_,
        send(dnla1, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PUSH))))
        .WillByDefault(make_basic_reply(true));
    ON_CALL(*protocol_message_handler_,
        send(dnla1, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PULL))))
        .WillByDefault(make_pull_reply(peers));

    for (auto peer : peers)
    {
        ON_CALL(*protocol_message_handler_,
            send(peer, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PUSH))))
            .WillByDefault(make_basic_reply(true));
    }

    auto peer_manager = make_peer_manager();
    peer_manager->start();
    EXPECT_TRUE(testutils::wait_for(
        [&] { return peer_manager->state() == PeerManagerFlow::State::RUNNING; }, 100));

    auto f = peer_manager->get_peers(requested_peer_count);
    EXPECT_EQ(f.wait_for(timeout_), std::future_status::ready);
    auto got_peers = f.get();
    ASSERT_THAT(got_peers, UnorderedElementsAreArray(peers));

    EXPECT_TRUE(Mock::VerifyAndClear(protocol_message_handler_.get()));

    std::vector<IPv4Address> new_peers(5);
    std::generate(new_peers.begin(), new_peers.end(), [&] { return random_ip_address(); });

    auto old_peers = peers;
    peers.clear();

    for (size_t i = 0; i != new_peers.size(); ++i)
    {
        ON_CALL(*protocol_message_handler_,
            send(old_peers[i],
                Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PING))))
            .WillByDefault(make_basic_reply(true));
        ON_CALL(*protocol_message_handler_,
            send(old_peers[i],
                Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PULL))))
            .WillByDefault(make_pull_reply({new_peers[i]}));
        ON_CALL(*protocol_message_handler_,
            send(new_peers[i],
                Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PUSH))))
            .WillByDefault(make_basic_reply(true));
        peers.push_back(old_peers[i]);
        peers.push_back(new_peers[i]);
    }

    for (size_t i = new_peers.size(); i != old_peers.size(); ++i)
    {
        ON_CALL(*protocol_message_handler_,
            send(old_peers[i],
                Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PING))))
            .WillByDefault(make_basic_reply(false));
    }

    f = peer_manager->get_peers(requested_peer_count);
    EXPECT_EQ(f.wait_for(timeout_), std::future_status::ready);
    got_peers = f.get();
    ASSERT_THAT(got_peers, UnorderedElementsAreArray(peers));
}

TEST_F(PeerManagerFlowTest, GetPeers_FromOtherPeers_Cause_WantMore)
{
    const size_t requested_peer_count = 15;
    const auto   dnla1                = random_ip_address();

    std::vector<IPv4Address> peers(10);
    std::generate(peers.begin(), peers.end(), [&] { return random_ip_address(); });

    ON_CALL(*dnl_config_loader_, load()).WillByDefault(Return(std::vector<IPv4Address> {dnla1}));
    dnl_config_->reload();

    ON_CALL(*protocol_message_handler_,
        send(dnla1, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PUSH))))
        .WillByDefault(make_basic_reply(true));
    ON_CALL(*protocol_message_handler_,
        send(dnla1, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PULL))))
        .WillByDefault(make_pull_reply(peers));

    for (auto peer : peers)
    {
        ON_CALL(*protocol_message_handler_,
            send(peer, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PUSH))))
            .WillByDefault(make_basic_reply(true));
    }

    auto peer_manager = make_peer_manager();
    peer_manager->start();
    EXPECT_TRUE(testutils::wait_for(
        [&] { return peer_manager->state() == PeerManagerFlow::State::RUNNING; }, 100));

    auto f = peer_manager->get_peers(requested_peer_count);
    EXPECT_EQ(f.wait_for(timeout_), std::future_status::ready);
    auto got_peers = f.get();
    ASSERT_THAT(got_peers, UnorderedElementsAreArray(peers));

    EXPECT_TRUE(Mock::VerifyAndClear(protocol_message_handler_.get()));

    std::vector<IPv4Address> new_peers(5);
    std::generate(new_peers.begin(), new_peers.end(), [&] { return random_ip_address(); });

    auto old_peers = peers;
    peers.clear();

    for (size_t i = 0; i != new_peers.size(); ++i)
    {
        ON_CALL(*protocol_message_handler_,
            send(old_peers[i],
                Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PING))))
            .WillByDefault(make_basic_reply(true));
        ON_CALL(*protocol_message_handler_,
            send(old_peers[i],
                Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PULL))))
            .WillByDefault(make_pull_reply({new_peers[i]}));
        ON_CALL(*protocol_message_handler_,
            send(new_peers[i],
                Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PUSH))))
            .WillByDefault(make_basic_reply(true));
        peers.push_back(old_peers[i]);
        peers.push_back(new_peers[i]);
    }

    for (size_t i = new_peers.size(); i != old_peers.size(); ++i)
    {
        ON_CALL(*protocol_message_handler_,
            send(old_peers[i],
                Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PING))))
            .WillByDefault(make_basic_reply(true));
        ON_CALL(*protocol_message_handler_,
            send(old_peers[i],
                Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PULL))))
            .WillByDefault(make_pull_reply({}));
        peers.push_back(old_peers[i]);
    }

    f = peer_manager->get_peers(requested_peer_count);
    EXPECT_EQ(f.wait_for(timeout_), std::future_status::ready);
    got_peers = f.get();
    ASSERT_THAT(got_peers, UnorderedElementsAreArray(peers));
}

TEST_F(PeerManagerFlowTest, HandlePush)
{
    const auto dnla1 = random_ip_address();
    const auto peer  = random_ip_address();

    ON_CALL(*dnl_config_loader_, load()).WillByDefault(Return(std::vector<IPv4Address> {dnla1}));
    dnl_config_->reload();

    ON_CALL(*protocol_message_handler_,
        send(dnla1, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PUSH))))
        .WillByDefault(make_basic_reply(true));
    ON_CALL(*protocol_message_handler_,
        send(dnla1, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PULL))))
        .WillByDefault(make_pull_reply({}));

    auto peer_manager = make_peer_manager();
    peer_manager->start();
    EXPECT_TRUE(testutils::wait_for(
        [&] { return peer_manager->state() == PeerManagerFlow::State::RUNNING; }, 100));

    PushMessage msg;
    msg.request_id = rng_.next<RequestId>();
    EXPECT_CALL(*protocol_message_handler_,
        send_reply(peer, AllOf(Pointee(Field(&BasicReply::request_id, msg.request_id)),
                             Pointee(Field(&BasicReply::request_message_code, msg.message_code)),
                             Pointee(Field(&BasicReply::status_code, StatusCode::OK)))))
        .Times(1)
        .WillOnce([](...) { return std::async(std::launch::deferred, [] { return true; }); });
    inbound_request_dispatcher_->on_message_received(peer, msg);

    EXPECT_CALL(*protocol_message_handler_,
        send(peer, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PING))))
        .Times(1)
        .WillOnce(make_basic_reply(true));
    EXPECT_CALL(*protocol_message_handler_,
        send(peer, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::BYE))))
        .Times(1);

    // Process all messages
    std::this_thread::sleep_for(std::chrono::milliseconds {25});

    auto f = peer_manager->get_peers(1);
    EXPECT_EQ(f.wait_for(timeout_), std::future_status::ready);
    ASSERT_THAT(f.get(), ElementsAre(peer));
}

TEST_F(PeerManagerFlowTest, HandleBye)
{
    const auto dnla1 = random_ip_address();
    const auto peer  = random_ip_address();

    ON_CALL(*dnl_config_loader_, load()).WillByDefault(Return(std::vector<IPv4Address> {dnla1}));
    dnl_config_->reload();

    ON_CALL(*protocol_message_handler_,
        send(dnla1, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PUSH))))
        .WillByDefault(make_basic_reply(true));
    ON_CALL(*protocol_message_handler_,
        send(dnla1, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PULL))))
        .WillByDefault(make_pull_reply({}));

    auto peer_manager = make_peer_manager();
    peer_manager->start();
    EXPECT_TRUE(testutils::wait_for(
        [&] { return peer_manager->state() == PeerManagerFlow::State::RUNNING; }, 100));

    PushMessage msg1;
    msg1.request_id = rng_.next<RequestId>();
    ON_CALL(*protocol_message_handler_,
        send_reply(peer, Pointee(Field(&BasicReply::request_id, msg1.request_id))))
        .WillByDefault([](...) { return std::async(std::launch::deferred, [] { return true; }); });
    inbound_request_dispatcher_->on_message_received(peer, msg1);

    // Process all messages
    std::this_thread::sleep_for(std::chrono::milliseconds {25});

    ByeMessage msg2;
    msg2.request_id = rng_.next<RequestId>();
    EXPECT_CALL(*protocol_message_handler_,
        send_reply(peer, Pointee(Field(&BasicReply::request_id, msg2.request_id))))
        .Times(0);
    inbound_request_dispatcher_->on_message_received(peer, msg2);

    // Process all messages
    std::this_thread::sleep_for(std::chrono::milliseconds {25});

    auto f = peer_manager->get_peers(1);
    EXPECT_EQ(f.wait_for(timeout_), std::future_status::ready);
    EXPECT_TRUE(f.get().empty());
}

TEST_F(PeerManagerFlowTest, HandlePing)
{
    const auto dnla1 = random_ip_address();
    const auto peer  = random_ip_address();

    ON_CALL(*dnl_config_loader_, load()).WillByDefault(Return(std::vector<IPv4Address> {dnla1}));
    dnl_config_->reload();

    ON_CALL(*protocol_message_handler_,
        send(dnla1, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PUSH))))
        .WillByDefault(make_basic_reply(true));
    ON_CALL(*protocol_message_handler_,
        send(dnla1, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PULL))))
        .WillByDefault(make_pull_reply({}));

    auto peer_manager = make_peer_manager();
    peer_manager->start();
    EXPECT_TRUE(testutils::wait_for(
        [&] { return peer_manager->state() == PeerManagerFlow::State::RUNNING; }, 100));

    PingMessage msg;
    msg.request_id = rng_.next<RequestId>();
    EXPECT_CALL(*protocol_message_handler_,
        send_reply(peer, AllOf(Pointee(Field(&BasicReply::request_id, msg.request_id)),
                             Pointee(Field(&BasicReply::request_message_code, msg.message_code)),
                             Pointee(Field(&BasicReply::status_code, StatusCode::OK)))))
        .Times(1)
        .WillOnce([](...) { return std::async(std::launch::deferred, [] { return true; }); });
    inbound_request_dispatcher_->on_message_received(peer, msg);

    // Process all messages
    std::this_thread::sleep_for(std::chrono::milliseconds {25});
}

TEST_F(PeerManagerFlowTest, HandlePull)
{
    std::vector<IPv4Address> peers(5);
    std::generate(peers.begin(), peers.end(), [&] { return random_ip_address(); });

    const auto dnla1 = random_ip_address();

    ON_CALL(*dnl_config_loader_, load()).WillByDefault(Return(std::vector<IPv4Address> {dnla1}));
    dnl_config_->reload();

    ON_CALL(*protocol_message_handler_,
        send(dnla1, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PUSH))))
        .WillByDefault(make_basic_reply(true));
    ON_CALL(*protocol_message_handler_,
        send(dnla1, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PULL))))
        .WillByDefault(make_pull_reply({}));

    auto peer_manager = make_peer_manager();
    peer_manager->start();
    EXPECT_TRUE(testutils::wait_for(
        [&] { return peer_manager->state() == PeerManagerFlow::State::RUNNING; }, 100));

    std::vector<PushMessage> push_messages(peers.size());
    for (size_t i = 0; i != peers.size(); ++i)
    {
        push_messages[i].request_id = rng_.next<RequestId>();
        ON_CALL(*protocol_message_handler_,
            send_reply(
                peers[i], Pointee(Field(&BasicReply::request_id, push_messages[i].request_id))))
            .WillByDefault(
                [](...) { return std::async(std::launch::deferred, [] { return true; }); });
        inbound_request_dispatcher_->on_message_received(peers[i], push_messages[i]);
    }

    // Process all messages
    std::this_thread::sleep_for(std::chrono::milliseconds {25});

    ON_CALL(*protocol_message_handler_,
        send(AnyOfArray(peers),
            Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PING))))
        .WillByDefault(make_basic_reply(true));

    PullMessage pull_message;
    pull_message.request_id    = rng_.next<RequestId>();
    pull_message.address_count = uint8_t(peers.size() + 1);
    auto pull_message_src      = random_ip_address();
    EXPECT_CALL(*protocol_message_handler_,
        send_reply(pull_message_src,
            AllOf(Pointee(Field(&BasicReply::request_id, pull_message.request_id)),
                Pointee(Field(&BasicReply::status_code, StatusCode::OK)),
                Pointee(Field(&BasicReply::request_message_code, pull_message.message_code)),
                ResultOf([](auto &&ptr) { return ptr.get(); },
                    WhenDynamicCastTo<PullReply *>(
                        Pointee(Field(&PullReply::peers, UnorderedElementsAreArray(peers))))))))
        .Times(1)
        .WillOnce([](...) { return std::async(std::launch::deferred, [] { return true; }); });

    inbound_request_dispatcher_->on_message_received(pull_message_src, pull_message);

    // Process all messages
    std::this_thread::sleep_for(std::chrono::milliseconds {25});
}

TEST_F(PeerManagerFlowTest, NotifiesStateChanges)
{
    const auto dnla1 = random_ip_address();

    ON_CALL(*dnl_config_loader_, load()).WillByDefault(Return(std::vector<IPv4Address> {dnla1}));
    dnl_config_->reload();

    ON_CALL(*protocol_message_handler_,
        send(dnla1, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PUSH))))
        .WillByDefault(make_basic_reply(true));
    ON_CALL(*protocol_message_handler_,
        send(dnla1, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PULL))))
        .WillByDefault(make_pull_reply({}));

    auto peer_manager = make_peer_manager();
    EXPECT_TRUE(peer_manager->register_listener(listener_));

    bool change_to_starting_notified = false;
    bool change_to_running_notified  = false;

    ON_CALL(*listener_, on_state_changed(PeerManagerFlow::State::STARTING)).WillByDefault([&](...) {
        change_to_starting_notified = true;
    });
    ON_CALL(*listener_, on_state_changed(PeerManagerFlow::State::RUNNING)).WillByDefault([&](...) {
        change_to_running_notified = true;
    });

    peer_manager->start();
    EXPECT_TRUE(testutils::wait_for([&] { return change_to_starting_notified; }, 100));
    EXPECT_TRUE(testutils::wait_for([&] { return change_to_running_notified; }, 100));

    bool change_to_stopping_notified = false;
    bool change_to_idle_notified     = false;

    ON_CALL(*listener_, on_state_changed(PeerManagerFlow::State::STOPPING)).WillByDefault([&](...) {
        change_to_stopping_notified = true;
    });
    ON_CALL(*listener_, on_state_changed(PeerManagerFlow::State::IDLE)).WillByDefault([&](...) {
        change_to_idle_notified = true;
    });

    peer_manager->stop();
    EXPECT_TRUE(change_to_stopping_notified);
    EXPECT_TRUE(change_to_idle_notified);
}

TEST_F(PeerManagerFlowTest, UnregisteredListenersAreNotNotifiedAnymore)
{
    const auto dnla1 = random_ip_address();

    ON_CALL(*dnl_config_loader_, load()).WillByDefault(Return(std::vector<IPv4Address> {dnla1}));
    dnl_config_->reload();

    ON_CALL(*protocol_message_handler_,
        send(dnla1, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PUSH))))
        .WillByDefault(make_basic_reply(true));
    ON_CALL(*protocol_message_handler_,
        send(dnla1, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PULL))))
        .WillByDefault(make_pull_reply({}));

    auto peer_manager = make_peer_manager();
    EXPECT_TRUE(peer_manager->register_listener(listener_));

    bool change_to_starting_notified = false;
    bool change_to_running_notified  = false;

    ON_CALL(*listener_, on_state_changed(PeerManagerFlow::State::STARTING)).WillByDefault([&](...) {
        change_to_starting_notified = true;
    });
    ON_CALL(*listener_, on_state_changed(PeerManagerFlow::State::RUNNING)).WillByDefault([&](...) {
        change_to_running_notified = true;
    });

    peer_manager->start();
    EXPECT_TRUE(testutils::wait_for([&] { return change_to_starting_notified; }, 100));
    EXPECT_TRUE(testutils::wait_for([&] { return change_to_running_notified; }, 100));

    EXPECT_TRUE(peer_manager->unregister_listener(listener_));

    bool change_to_stopping_notified = false;
    bool change_to_idle_notified     = false;

    ON_CALL(*listener_, on_state_changed(PeerManagerFlow::State::STOPPING)).WillByDefault([&](...) {
        change_to_stopping_notified = true;
    });
    ON_CALL(*listener_, on_state_changed(PeerManagerFlow::State::IDLE)).WillByDefault([&](...) {
        change_to_idle_notified = true;
    });

    peer_manager->stop();
    EXPECT_FALSE(change_to_stopping_notified);
    EXPECT_FALSE(change_to_idle_notified);
}

TEST_F(PeerManagerFlowTest, PreloadPeers)
{
    const auto dnla1 = random_ip_address();
    const auto dnla2 = random_ip_address();

    std::vector<IPv4Address> peers1(5);
    std::generate(peers1.begin(), peers1.end(), [&] { return random_ip_address(); });

    std::vector<IPv4Address> peers2(5);
    std::generate(peers2.begin(), peers2.end(), [&] { return random_ip_address(); });

    ON_CALL(*dnl_config_loader_, load())
        .WillByDefault(Return(std::vector<IPv4Address> {dnla1, dnla2}));
    dnl_config_->reload();

    EXPECT_CALL(*protocol_message_handler_,
        send(dnla1, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PUSH))))
        .Times(AnyNumber())
        .WillRepeatedly(make_basic_reply(true));
    EXPECT_CALL(*protocol_message_handler_,
        send(dnla1, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PULL))))
        .Times(AnyNumber())
        .WillRepeatedly(make_pull_reply(peers1));

    EXPECT_CALL(*protocol_message_handler_,
        send(dnla2, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PUSH))))
        .Times(AnyNumber())
        .WillRepeatedly(make_basic_reply(true));
    EXPECT_CALL(*protocol_message_handler_,
        send(dnla2, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PULL))))
        .Times(AnyNumber())
        .WillRepeatedly(make_pull_reply(peers2));

    for (auto peer : peers1)
    {
        EXPECT_CALL(*protocol_message_handler_,
            send(peer, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PUSH))))
            .Times(1)
            .WillOnce(make_basic_reply(true));
    }
    for (auto peer : peers2)
    {
        EXPECT_CALL(*protocol_message_handler_,
            send(peer, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PUSH))))
            .Times(1)
            .WillOnce(make_basic_reply(true));
    }

    auto peer_manager = std::make_unique<PeerManagerFlowImpl>(protocol_message_handler_,
        inbound_request_dispatcher_, dnl_config_, executer_, io_executer_, 10);
    peer_manager->start();
    EXPECT_TRUE(testutils::wait_for(
        [&] { return peer_manager->state() == PeerManagerFlow::State::RUNNING; }, 100));

    // Wait a little bit more until are PUSH messages are sent
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    Mock::VerifyAndClearExpectations(protocol_message_handler_.get());

    for (auto peer : peers1)
    {
        EXPECT_CALL(*protocol_message_handler_,
            send(peer, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::BYE))))
            .Times(1);
    }
    for (auto peer : peers2)
    {
        EXPECT_CALL(*protocol_message_handler_,
            send(peer, Pointee(Field(&sand::protocol::Message::message_code, MessageCode::BYE))))
            .Times(1);
    }

    peer_manager->stop();
    Mock::VerifyAndClearExpectations(protocol_message_handler_.get());
}
