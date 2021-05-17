#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <future>
#include <memory>

#include "dnlconfig.hpp"
#include "inboundrequestdispatcher.hpp"
#include "iothreadpool.hpp"
#include "peermanager.hpp"
#include "random.hpp"
#include "threadpool.hpp"

#include "dnlconfigloader_mock.hpp"
#include "protocolmessagehandler_mock.hpp"

using namespace ::testing;
using namespace ::sand::flows;
using namespace ::sand::protocol;
using namespace ::sand::network;
using namespace ::sand::utils;

namespace
{
class PeerManagerTest : public Test
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
    }

    std::unique_ptr<PeerManager> make_peer_manager()
    {
        return std::make_unique<PeerManager>(protocol_message_handler_, inbound_request_dispatcher_,
            dnl_config_, executer_, io_executer_);
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

    static auto make_ping_reply(bool ok)
    {
        return [=](auto, auto msg) {
            std::promise<std::unique_ptr<BasicReply>> promise;

            auto *_msg = dynamic_cast<PingMessage *>(msg.get());
            EXPECT_TRUE(_msg);
            EXPECT_EQ(_msg->message_code, MessageCode::PING);

            auto reply         = std::make_unique<BasicReply>(_msg->message_code);
            reply->request_id  = _msg->request_id;
            reply->status_code = ok ? StatusCode::OK : StatusCode::UNREACHABLE;
            promise.set_value(std::move(reply));

            return promise.get_future();
        };
    }

    std::shared_ptr<ProtocolMessageHandlerMock> protocol_message_handler_;
    std::shared_ptr<InboundRequestDispatcher>   inbound_request_dispatcher_;
    DNLConfigLoaderMock *                       dnl_config_loader_;
    std::shared_ptr<DNLConfig>                  dnl_config_;
    std::shared_ptr<Executer>                   executer_;
    std::shared_ptr<Executer>                   io_executer_;
    std::chrono::milliseconds                   timeout_ {100};
    Random                                      rng_;
};
}  // namespace

TEST_F(PeerManagerTest, GetPeers_FromDNL_DNLConfigEmpty)
{
    const size_t requested_peer_count = 3;

    ON_CALL(*dnl_config_loader_, load()).WillByDefault(Return(std::vector<IPv4Address> {}));
    dnl_config_->reload();

    auto peer_manager = make_peer_manager();

    auto f = peer_manager->get_peers(requested_peer_count);
    EXPECT_EQ(f.wait_for(timeout_), std::future_status::ready);
    EXPECT_TRUE(f.get().empty());
}

TEST_F(PeerManagerTest, GetPeers_FromDNL_1DownDNLNode)
{
    const size_t requested_peer_count = 3;
    const auto   dnla1                = random_ip_address();

    ON_CALL(*dnl_config_loader_, load()).WillByDefault(Return(std::vector<IPv4Address> {dnla1}));
    dnl_config_->reload();

    EXPECT_CALL(*protocol_message_handler_, send(dnla1, _)).Times(1).WillOnce(make_pull_reply({}));

    auto peer_manager = make_peer_manager();

    auto f = peer_manager->get_peers(requested_peer_count);
    EXPECT_EQ(f.wait_for(timeout_), std::future_status::ready);
    EXPECT_TRUE(f.get().empty());
}

TEST_F(PeerManagerTest, GetPeers_FromDNL_1DownDNLNode_1UpDNLNode)
{
    const size_t requested_peer_count = 10;
    const auto   dnla1                = random_ip_address();
    const auto   dnla2                = random_ip_address();

    std::vector<IPv4Address> peers(8);
    std::generate(peers.begin(), peers.end(), [&] { return random_ip_address(); });

    ON_CALL(*dnl_config_loader_, load())
        .WillByDefault(Return(std::vector<IPv4Address> {dnla1, dnla2}));
    dnl_config_->reload();

    EXPECT_CALL(*protocol_message_handler_, send(dnla1, _)).Times(1).WillOnce(make_pull_reply({}));
    EXPECT_CALL(*protocol_message_handler_, send(dnla2, _))
        .Times(1)
        .WillOnce(make_pull_reply(peers));

    for (auto peer : peers)
    {
        EXPECT_CALL(*protocol_message_handler_, send(peer, _)).Times(1);
    }
    ON_CALL(*protocol_message_handler_, send(AnyOfArray(peers), _))
        .WillByDefault(make_ping_reply(true));

    auto peer_manager = make_peer_manager();

    auto f = peer_manager->get_peers(requested_peer_count);
    EXPECT_EQ(f.wait_for(timeout_), std::future_status::ready);
    ASSERT_THAT(f.get(), UnorderedElementsAreArray(peers));
}

TEST_F(PeerManagerTest, GetPeers_FromDNL_2UpDNLNodes_FirstReturnsAllRequestedPeers)
{
    const size_t requested_peer_count = 10;
    const auto   dnla1                = random_ip_address();
    const auto   dnla2                = random_ip_address();

    std::vector<IPv4Address> peers(10);
    std::generate(peers.begin(), peers.end(), [&] { return random_ip_address(); });

    ON_CALL(*dnl_config_loader_, load())
        .WillByDefault(Return(std::vector<IPv4Address> {dnla1, dnla2}));
    dnl_config_->reload();

    EXPECT_CALL(*protocol_message_handler_, send(AnyOf(dnla1, dnla2), _))
        .Times(1)
        .WillOnce(make_pull_reply(peers));

    for (auto peer : peers)
    {
        EXPECT_CALL(*protocol_message_handler_, send(peer, _)).Times(1);
    }
    ON_CALL(*protocol_message_handler_, send(AnyOfArray(peers), _))
        .WillByDefault(make_ping_reply(true));

    auto peer_manager = make_peer_manager();

    auto f = peer_manager->get_peers(requested_peer_count);
    EXPECT_EQ(f.wait_for(timeout_), std::future_status::ready);
    ASSERT_THAT(f.get(), UnorderedElementsAreArray(peers));
}

TEST_F(PeerManagerTest, GetPeers_FromDNL_2UpDNLNodes_EachReturnsSomePeers)
{
    const size_t requested_peer_count        = 10;
    const size_t peers_returned_by_first_dnl = 7;
    const auto   dnla1                       = random_ip_address();
    const auto   dnla2                       = random_ip_address();

    std::vector<IPv4Address> peers(10);
    std::generate(peers.begin(), peers.end(), [&] { return random_ip_address(); });

    ON_CALL(*dnl_config_loader_, load())
        .WillByDefault(Return(std::vector<IPv4Address> {dnla1, dnla2}));
    dnl_config_->reload();

    EXPECT_CALL(*protocol_message_handler_, send(dnla1, _))
        .Times(1)
        .WillOnce(make_pull_reply(std::vector<IPv4Address>(
            peers.cbegin(), peers.cbegin() + peers_returned_by_first_dnl)));
    EXPECT_CALL(*protocol_message_handler_, send(dnla2, _))
        .Times(1)
        .WillOnce(make_pull_reply(
            std::vector<IPv4Address>(peers.cbegin() + peers_returned_by_first_dnl, peers.cend())));

    for (auto peer : peers)
    {
        EXPECT_CALL(*protocol_message_handler_, send(peer, _)).Times(1);
    }
    ON_CALL(*protocol_message_handler_, send(AnyOfArray(peers), _))
        .WillByDefault(make_ping_reply(true));

    auto peer_manager = make_peer_manager();

    auto f = peer_manager->get_peers(requested_peer_count);
    EXPECT_EQ(f.wait_for(timeout_), std::future_status::ready);
    ASSERT_THAT(f.get(), UnorderedElementsAreArray(peers));
}

TEST_F(PeerManagerTest, GetPeers_FromDNL_1UpDNLNode_ReturnsMorePeersThanRequested)
{
    const size_t requested_peer_count = 10;
    const auto   dnla1                = random_ip_address();

    std::vector<IPv4Address> peers(15);
    std::generate(peers.begin(), peers.end(), [&] { return random_ip_address(); });

    ON_CALL(*dnl_config_loader_, load()).WillByDefault(Return(std::vector<IPv4Address> {dnla1}));
    dnl_config_->reload();

    EXPECT_CALL(*protocol_message_handler_, send(dnla1, _))
        .Times(1)
        .WillOnce(make_pull_reply(peers));

    for (auto peer : peers)
    {
        EXPECT_CALL(*protocol_message_handler_, send(peer, _)).Times(1);
    }
    ON_CALL(*protocol_message_handler_, send(AnyOfArray(peers), _))
        .WillByDefault(make_ping_reply(true));

    auto peer_manager = make_peer_manager();

    auto f = peer_manager->get_peers(requested_peer_count);
    EXPECT_EQ(f.wait_for(timeout_), std::future_status::ready);

    auto got_peers = f.get();
    EXPECT_EQ(got_peers.size(), requested_peer_count);
    ASSERT_THAT(got_peers, IsSubsetOf(peers));
}

TEST_F(PeerManagerTest, GetPeers_FromDNL_1UpDNLNode_SomePeersDead)
{
    const size_t requested_peer_count = 10;
    const size_t dead_peers_count     = 3;
    const auto   dnla1                = random_ip_address();

    std::vector<IPv4Address> peers(10);
    std::generate(peers.begin(), peers.end(), [&] { return random_ip_address(); });
    std::vector<IPv4Address> peers_from_dnln2(3);
    std::vector<IPv4Address> alive_peers(peers.cbegin() + dead_peers_count, peers.cend());
    std::vector<IPv4Address> dead_peers(peers.cbegin(), peers.cbegin() + dead_peers_count);

    ON_CALL(*dnl_config_loader_, load()).WillByDefault(Return(std::vector<IPv4Address> {dnla1}));
    dnl_config_->reload();

    EXPECT_CALL(*protocol_message_handler_, send(dnla1, _))
        .Times(1)
        .WillOnce(make_pull_reply(peers));

    for (auto peer : peers)
    {
        EXPECT_CALL(*protocol_message_handler_, send(peer, _)).Times(1);
    }
    ON_CALL(*protocol_message_handler_, send(AnyOfArray(alive_peers), _))
        .WillByDefault(make_ping_reply(true));
    ON_CALL(*protocol_message_handler_, send(AnyOfArray(dead_peers), _))
        .WillByDefault(make_ping_reply(false));

    auto peer_manager = make_peer_manager();

    auto f = peer_manager->get_peers(requested_peer_count);
    EXPECT_EQ(f.wait_for(timeout_), std::future_status::ready);
    ASSERT_THAT(f.get(), UnorderedElementsAreArray(alive_peers));
}

TEST_F(PeerManagerTest, GetPeers_FromDNL_2UpDNLNodes_SomePeersDead_UseSecondDNLAsBackup)
{
    const size_t requested_peer_count = 10;
    const size_t dead_peers_count     = 3;
    const auto   dnla1                = random_ip_address();
    const auto   dnla2                = random_ip_address();

    std::vector<IPv4Address> peers_from_dnln1(10);
    std::generate(
        peers_from_dnln1.begin(), peers_from_dnln1.end(), [&] { return random_ip_address(); });
    std::vector<IPv4Address> peers_from_dnln2(3);
    std::generate(
        peers_from_dnln2.begin(), peers_from_dnln2.end(), [&] { return random_ip_address(); });
    std::vector<IPv4Address> alive_peers(10);
    std::copy(peers_from_dnln2.cbegin(), peers_from_dnln2.cend(),
        std::copy(peers_from_dnln1.cbegin() + dead_peers_count, peers_from_dnln1.cend(),
            alive_peers.begin()));
    std::vector<IPv4Address> dead_peers(
        peers_from_dnln1.cbegin(), peers_from_dnln1.cbegin() + dead_peers_count);

    ON_CALL(*dnl_config_loader_, load())
        .WillByDefault(Return(std::vector<IPv4Address> {dnla1, dnla2}));
    dnl_config_->reload();

    EXPECT_CALL(*protocol_message_handler_, send(dnla1, _))
        .Times(1)
        .WillOnce(make_pull_reply(peers_from_dnln1));
    EXPECT_CALL(*protocol_message_handler_, send(dnla2, _))
        .Times(1)
        .WillOnce(make_pull_reply(peers_from_dnln2));

    for (auto peer : peers_from_dnln1)
    {
        EXPECT_CALL(*protocol_message_handler_, send(peer, _)).Times(1);
    }
    for (auto peer : peers_from_dnln2)
    {
        EXPECT_CALL(*protocol_message_handler_, send(peer, _)).Times(1);
    }
    ON_CALL(*protocol_message_handler_, send(AnyOfArray(alive_peers), _))
        .WillByDefault(make_ping_reply(true));
    ON_CALL(*protocol_message_handler_, send(AnyOfArray(dead_peers), _))
        .WillByDefault(make_ping_reply(false));

    auto peer_manager = make_peer_manager();

    auto f = peer_manager->get_peers(requested_peer_count);
    EXPECT_EQ(f.wait_for(timeout_), std::future_status::ready);
    ASSERT_THAT(f.get(), UnorderedElementsAreArray(alive_peers));
}

TEST_F(PeerManagerTest, GetPeers_FromCache_AllAlive)
{
    const size_t requested_peer_count = 10;
    const auto   dnla1                = random_ip_address();

    std::vector<IPv4Address> peers(10);
    std::generate(peers.begin(), peers.end(), [&] { return random_ip_address(); });

    ON_CALL(*dnl_config_loader_, load()).WillByDefault(Return(std::vector<IPv4Address> {dnla1}));
    dnl_config_->reload();

    EXPECT_CALL(*protocol_message_handler_, send(dnla1, _))
        .Times(1)
        .WillOnce(make_pull_reply(peers));

    for (auto peer : peers)
    {
        EXPECT_CALL(*protocol_message_handler_, send(peer, _)).Times(2);
    }
    ON_CALL(*protocol_message_handler_, send(AnyOfArray(peers), _))
        .WillByDefault(make_ping_reply(true));

    auto peer_manager = make_peer_manager();

    // Get from DNL
    auto f = peer_manager->get_peers(requested_peer_count);
    EXPECT_EQ(f.wait_for(timeout_), std::future_status::ready);
    ASSERT_THAT(f.get(), UnorderedElementsAreArray(peers));

    // Get from cache
    f = peer_manager->get_peers(requested_peer_count);
    EXPECT_EQ(f.wait_for(timeout_), std::future_status::ready);
    ASSERT_THAT(f.get(), UnorderedElementsAreArray(peers));
}

TEST_F(PeerManagerTest, GetPeers_FromCache_SomePeersDied)
{
    const size_t requested_peer_count = 10;
    const size_t dead_peers_count     = 3;
    const auto   dnla1                = random_ip_address();

    std::vector<IPv4Address> peers(10);
    std::generate(peers.begin(), peers.end(), [&] { return random_ip_address(); });

    ON_CALL(*dnl_config_loader_, load()).WillByDefault(Return(std::vector<IPv4Address> {dnla1}));
    dnl_config_->reload();

    ON_CALL(*protocol_message_handler_, send(dnla1, _)).WillByDefault(make_pull_reply(peers));

    ON_CALL(*protocol_message_handler_, send(AnyOfArray(peers), _))
        .WillByDefault(make_ping_reply(true));

    auto peer_manager = make_peer_manager();

    // Get from DNL
    auto f = peer_manager->get_peers(requested_peer_count);
    EXPECT_EQ(f.wait_for(timeout_), std::future_status::ready);
    ASSERT_THAT(f.get(), UnorderedElementsAreArray(peers));

    EXPECT_TRUE(Mock::VerifyAndClear(protocol_message_handler_.get()));

    std::vector<IPv4Address> dead_peers(peers.cbegin(), peers.cbegin() + dead_peers_count);
    std::vector<IPv4Address> alive_peers(peers.cbegin() + dead_peers_count, peers.cend());

    ON_CALL(*protocol_message_handler_, send(dnla1, _)).WillByDefault(make_pull_reply(alive_peers));
    ON_CALL(*protocol_message_handler_,
        send(AnyOfArray(dead_peers),
            Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PING))))
        .WillByDefault(make_ping_reply(false));
    ON_CALL(*protocol_message_handler_,
        send(AnyOfArray(alive_peers),
            Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PING))))
        .WillByDefault(make_ping_reply(true));
    ON_CALL(*protocol_message_handler_,
        send(AnyOfArray(alive_peers),
            Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PULL))))
        .WillByDefault(make_pull_reply({}));

    // Get from cache
    f = peer_manager->get_peers(requested_peer_count);
    EXPECT_EQ(f.wait_for(timeout_), std::future_status::ready);
    ASSERT_THAT(f.get(), UnorderedElementsAreArray(alive_peers));
}

TEST_F(PeerManagerTest, GetPeers_FromCache_SomePeersDied_ReplenishFromDNL)
{
    const size_t requested_peer_count = 10;
    const size_t dead_peers_count     = 3;
    const auto   dnla1                = random_ip_address();

    std::vector<IPv4Address> peers(10);
    std::generate(peers.begin(), peers.end(), [&] { return random_ip_address(); });

    ON_CALL(*dnl_config_loader_, load()).WillByDefault(Return(std::vector<IPv4Address> {dnla1}));
    dnl_config_->reload();

    ON_CALL(*protocol_message_handler_, send(dnla1, _)).WillByDefault(make_pull_reply(peers));

    ON_CALL(*protocol_message_handler_, send(AnyOfArray(peers), _))
        .WillByDefault(make_ping_reply(true));

    auto peer_manager = make_peer_manager();

    // Get from DNL
    auto f = peer_manager->get_peers(requested_peer_count);
    EXPECT_EQ(f.wait_for(timeout_), std::future_status::ready);
    ASSERT_THAT(f.get(), UnorderedElementsAreArray(peers));

    EXPECT_TRUE(Mock::VerifyAndClear(protocol_message_handler_.get()));

    std::vector<IPv4Address> dead_peers(peers.cbegin(), peers.cbegin() + dead_peers_count);
    std::vector<IPv4Address> alive_peers(peers.cbegin() + dead_peers_count, peers.cend());
    std::vector<IPv4Address> new_peers(5);
    std::generate(new_peers.begin(), new_peers.end(), [&] { return random_ip_address(); });
    alive_peers.insert(alive_peers.end(), new_peers.cbegin(), new_peers.cend());

    ON_CALL(*protocol_message_handler_, send(dnla1, _)).WillByDefault(make_pull_reply(alive_peers));
    ON_CALL(*protocol_message_handler_,
        send(AnyOfArray(dead_peers),
            Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PING))))
        .WillByDefault(make_ping_reply(false));
    ON_CALL(*protocol_message_handler_,
        send(AnyOfArray(alive_peers),
            Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PING))))
        .WillByDefault(make_ping_reply(true));
    ON_CALL(*protocol_message_handler_,
        send(AnyOfArray(alive_peers),
            Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PULL))))
        .WillByDefault(make_pull_reply({}));

    // Get from cache
    f = peer_manager->get_peers(requested_peer_count);
    EXPECT_EQ(f.wait_for(timeout_), std::future_status::ready);
    auto got_peers = f.get();
    EXPECT_EQ(got_peers.size(), requested_peer_count);
    ASSERT_THAT(got_peers, IsSubsetOf(alive_peers));
}

TEST_F(PeerManagerTest, GetPeers_FromCache_SomePeersDied_ReplenishFromOtherPeers)
{
    const size_t requested_peer_count = 10;
    const size_t dead_peers_count     = 3;
    const auto   dnla1                = random_ip_address();

    std::vector<IPv4Address> peers(10);
    std::generate(peers.begin(), peers.end(), [&] { return random_ip_address(); });

    ON_CALL(*dnl_config_loader_, load()).WillByDefault(Return(std::vector<IPv4Address> {dnla1}));
    dnl_config_->reload();

    ON_CALL(*protocol_message_handler_, send(dnla1, _)).WillByDefault(make_pull_reply(peers));

    ON_CALL(*protocol_message_handler_, send(AnyOfArray(peers), _))
        .WillByDefault(make_ping_reply(true));

    auto peer_manager = make_peer_manager();

    // Get from DNL
    auto f = peer_manager->get_peers(requested_peer_count);
    EXPECT_EQ(f.wait_for(timeout_), std::future_status::ready);
    ASSERT_THAT(f.get(), UnorderedElementsAreArray(peers));

    EXPECT_TRUE(Mock::VerifyAndClear(protocol_message_handler_.get()));

    std::vector<IPv4Address> dead_peers(peers.cbegin(), peers.cbegin() + dead_peers_count);
    std::vector<IPv4Address> alive_peers(peers.cbegin() + dead_peers_count, peers.cend());
    std::vector<IPv4Address> new_peers(5);
    std::generate(new_peers.begin(), new_peers.end(), [&] { return random_ip_address(); });

    ON_CALL(*protocol_message_handler_, send(dnla1, _)).WillByDefault(make_pull_reply(alive_peers));
    ON_CALL(*protocol_message_handler_,
        send(AnyOfArray(dead_peers),
            Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PING))))
        .WillByDefault(make_ping_reply(false));
    ON_CALL(*protocol_message_handler_,
        send(AnyOfArray(alive_peers),
            Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PING))))
        .WillByDefault(make_ping_reply(true));
    ON_CALL(*protocol_message_handler_,
        send(AnyOfArray(new_peers),
            Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PING))))
        .WillByDefault(make_ping_reply(true));

    for (size_t i = 0, j = 0; i != alive_peers.size(); ++i)
    {
        if (j < new_peers.size())
        {
            ON_CALL(*protocol_message_handler_,
                send(alive_peers[i],
                    Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PULL))))
                .WillByDefault(make_pull_reply({new_peers[j]}));
            ++j;
        }
        else
        {
            ON_CALL(*protocol_message_handler_,
                send(alive_peers[i],
                    Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PULL))))
                .WillByDefault(make_pull_reply({}));
        }
    }

    // Get from cache
    f = peer_manager->get_peers(requested_peer_count);
    EXPECT_EQ(f.wait_for(timeout_), std::future_status::ready);
    auto got_peers = f.get();
    EXPECT_EQ(got_peers.size(), requested_peer_count);

    alive_peers.insert(alive_peers.end(), new_peers.cbegin(), new_peers.cend());
    ASSERT_THAT(got_peers, IsSubsetOf(alive_peers));
}

TEST_F(PeerManagerTest, GetPeers_FromCache_WantMore_ReplenishFromDNL)
{
    const size_t requested_peer_count = 10;
    const auto   dnla1                = random_ip_address();

    std::vector<IPv4Address> peers(10);
    std::generate(peers.begin(), peers.end(), [&] { return random_ip_address(); });

    ON_CALL(*dnl_config_loader_, load()).WillByDefault(Return(std::vector<IPv4Address> {dnla1}));
    dnl_config_->reload();

    ON_CALL(*protocol_message_handler_, send(dnla1, _)).WillByDefault(make_pull_reply(peers));

    ON_CALL(*protocol_message_handler_, send(AnyOfArray(peers), _))
        .WillByDefault(make_ping_reply(true));

    auto peer_manager = make_peer_manager();

    // Get from DNL
    auto f = peer_manager->get_peers(requested_peer_count);
    EXPECT_EQ(f.wait_for(timeout_), std::future_status::ready);
    ASSERT_THAT(f.get(), UnorderedElementsAreArray(peers));

    EXPECT_TRUE(Mock::VerifyAndClear(protocol_message_handler_.get()));

    std::vector<IPv4Address> new_peers(5);
    std::generate(new_peers.begin(), new_peers.end(), [&] { return random_ip_address(); });
    peers.insert(peers.end(), new_peers.cbegin(), new_peers.cend());

    ON_CALL(*protocol_message_handler_, send(dnla1, _)).WillByDefault(make_pull_reply(peers));
    ON_CALL(*protocol_message_handler_,
        send(AnyOfArray(peers),
            Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PING))))
        .WillByDefault(make_ping_reply(true));
    ON_CALL(*protocol_message_handler_,
        send(AnyOfArray(peers),
            Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PULL))))
        .WillByDefault(make_pull_reply({}));

    // Get from cache
    f = peer_manager->get_peers(int(requested_peer_count + new_peers.size() / 2));
    EXPECT_EQ(f.wait_for(timeout_), std::future_status::ready);
    auto got_peers = f.get();
    EXPECT_EQ(got_peers.size(), requested_peer_count + new_peers.size() / 2);
    ASSERT_THAT(got_peers, IsSubsetOf(peers));
}

TEST_F(PeerManagerTest, GetPeers_FromCache_WantMore_ReplenishFromOtherPeers)
{
    const size_t requested_peer_count = 10;
    const auto   dnla1                = random_ip_address();

    std::vector<IPv4Address> peers(10);
    std::generate(peers.begin(), peers.end(), [&] { return random_ip_address(); });

    ON_CALL(*dnl_config_loader_, load()).WillByDefault(Return(std::vector<IPv4Address> {dnla1}));
    dnl_config_->reload();

    ON_CALL(*protocol_message_handler_, send(dnla1, _)).WillByDefault(make_pull_reply(peers));

    ON_CALL(*protocol_message_handler_, send(AnyOfArray(peers), _))
        .WillByDefault(make_ping_reply(true));

    auto peer_manager = make_peer_manager();

    // Get from DNL
    auto f = peer_manager->get_peers(requested_peer_count);
    EXPECT_EQ(f.wait_for(timeout_), std::future_status::ready);
    ASSERT_THAT(f.get(), UnorderedElementsAreArray(peers));

    EXPECT_TRUE(Mock::VerifyAndClear(protocol_message_handler_.get()));

    std::vector<IPv4Address> new_peers(5);
    std::generate(new_peers.begin(), new_peers.end(), [&] { return random_ip_address(); });

    ON_CALL(*protocol_message_handler_, send(dnla1, _)).WillByDefault(make_pull_reply(peers));
    ON_CALL(*protocol_message_handler_,
        send(AnyOfArray(peers),
            Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PING))))
        .WillByDefault(make_ping_reply(true));
    ON_CALL(*protocol_message_handler_,
        send(AnyOfArray(new_peers),
            Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PING))))
        .WillByDefault(make_ping_reply(true));

    for (size_t i = 0, j = 0; i != peers.size(); ++i)
    {
        if (j < new_peers.size())
        {
            ON_CALL(*protocol_message_handler_,
                send(peers[i],
                    Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PULL))))
                .WillByDefault(make_pull_reply({new_peers[j]}));
            ++j;
        }
        else
        {
            ON_CALL(*protocol_message_handler_,
                send(peers[i],
                    Pointee(Field(&sand::protocol::Message::message_code, MessageCode::PULL))))
                .WillByDefault(make_pull_reply({}));
        }
    }

    // Get from cache
    f = peer_manager->get_peers(requested_peer_count);
    EXPECT_EQ(f.wait_for(timeout_), std::future_status::ready);
    auto got_peers = f.get();
    EXPECT_EQ(got_peers.size(), requested_peer_count);

    peers.insert(peers.end(), new_peers.cbegin(), new_peers.cend());
    ASSERT_THAT(got_peers, IsSubsetOf(peers));
}
