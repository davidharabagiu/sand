#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <future>
#include <memory>
#include <utility>
#include <vector>

#include "config.hpp"
#include "filelocatorflowimpl.hpp"
#include "inboundrequestdispatcher.hpp"
#include "random.hpp"
#include "searchhandleimpl.hpp"
#include "threadpool.hpp"
#include "transferhandleimpl.hpp"

#include "configloader_mock.hpp"
#include "filehashinterpreter_mock.hpp"
#include "filelocatorflowlistener_mock.hpp"
#include "filestorage_mock.hpp"
#include "peeraddressprovider_mock.hpp"
#include "protocolmessagehandler_mock.hpp"
#include "secretdatainterpreter_mock.hpp"

using namespace ::sand::flows;
using namespace ::sand::utils;
using namespace ::sand::protocol;
using namespace ::sand::storage;
using namespace ::sand::config;
using namespace ::testing;

namespace
{
class FileLocatorFlowTest : public Test
{
protected:
    void SetUp() override
    {
        protocol_message_handler_ = std::make_shared<NiceMock<ProtocolMessageHandlerMock>>();
        inbound_request_dispatcher_ =
            std::make_shared<InboundRequestDispatcher>(protocol_message_handler_);
        peer_address_provider_   = std::make_shared<NiceMock<PeerAddressProviderMock>>();
        file_storage_            = std::make_shared<NiceMock<FileStorageMock>>();
        file_hash_interpreter_   = new NiceMock<FileHashInterpreterMock>();
        secret_data_interpreter_ = std::make_shared<NiceMock<SecretDataInterpreterMock>>();
        thread_pool_             = std::make_shared<ThreadPool>();
        listener_                = std::make_shared<NiceMock<FileLocatorFlowListenerMock>>();
    }

    std::unique_ptr<FileLocatorFlow> make_flow(uint8_t search_message_ttl = 3,
        int search_timeout_sec = 0, int routing_table_entry_expiration_time_sec = 0)
    {
        ON_CALL(config_loader_, load())
            .WillByDefault(Return(std::map<std::string, std::any> {
                {ConfigKey(ConfigKey::SEARCH_PROPAGATION_DEGREE).to_string(),
                    (long long) {search_propagation_degree_}},
                {ConfigKey(ConfigKey::SEARCH_TIMEOUT).to_string(),
                    (long long) {search_timeout_sec}},
                {ConfigKey(ConfigKey::SEARCH_MESSAGE_TTL).to_string(),
                    (long long) {search_message_ttl}},
                {ConfigKey(ConfigKey::ROUTING_TABLE_ENTRY_TIMEOUT).to_string(),
                    (long long) {routing_table_entry_expiration_time_sec}}}));
        return std::make_unique<FileLocatorFlowImpl>(protocol_message_handler_,
            inbound_request_dispatcher_, peer_address_provider_, file_storage_,
            std::unique_ptr<FileHashInterpreter>(file_hash_interpreter_), secret_data_interpreter_,
            thread_pool_, thread_pool_, pub_key_, pri_key_, Config {config_loader_});
    }

    static auto make_get_peers_action(const std::vector<IPv4Address> &peers)
    {
        return [=](int /*count*/, const std::set<IPv4Address> & /*exclude*/) {
            std::promise<std::vector<IPv4Address>> promise;
            promise.set_value(peers);
            return promise.get_future();
        };
    }

    static auto make_send_message_action(bool                                        success,
        std::function<void(IPv4Address, std::unique_ptr<sand::protocol::Message>)> &&also_do_this =
            {})
    {
        return [=](IPv4Address addr, std::unique_ptr<sand::protocol::Message> msg) {
            auto reply         = std::make_unique<BasicReply>(msg->message_code);
            reply->request_id  = msg->request_id;
            reply->status_code = success ? StatusCode::OK : StatusCode::UNREACHABLE;
            std::promise<std::unique_ptr<BasicReply>> promise;
            promise.set_value(std::move(reply));
            if (also_do_this)
            {
                also_do_this(addr, std::move(msg));
            }
            return promise.get_future();
        };
    }

    static auto make_send_reply_action()
    {
        return [](auto /*addr*/, auto /*reply*/) {
            std::promise<bool> promise;
            promise.set_value(true);
            return promise.get_future();
        };
    }

    std::shared_ptr<ProtocolMessageHandlerMock>  protocol_message_handler_;
    std::shared_ptr<InboundRequestDispatcher>    inbound_request_dispatcher_;
    std::shared_ptr<PeerAddressProviderMock>     peer_address_provider_;
    std::shared_ptr<FileStorageMock>             file_storage_;
    FileHashInterpreterMock *                    file_hash_interpreter_;
    std::shared_ptr<SecretDataInterpreterMock>   secret_data_interpreter_;
    std::shared_ptr<Executer>                    thread_pool_;
    std::shared_ptr<FileLocatorFlowListenerMock> listener_;
    NiceMock<ConfigLoaderMock>                   config_loader_;
    Random                                       rng_;
    const std::string                            pub_key_                   = "pub_key";
    const std::string                            pri_key_                   = "pri_key";
    const int                                    search_propagation_degree_ = 5;
};
}  // namespace

TEST_F(FileLocatorFlowTest, StartStop_StateChanges)
{
    auto flow = make_flow();
    EXPECT_EQ(flow->state(), FileLocatorFlow::State::IDLE);

    flow->start();
    EXPECT_EQ(flow->state(), FileLocatorFlow::State::RUNNING);

    flow->stop();
    EXPECT_EQ(flow->state(), FileLocatorFlow::State::IDLE);
}

TEST_F(FileLocatorFlowTest, StartStop_StateChangesAreNotified)
{
    auto flow = make_flow();
    flow->register_listener(listener_);

    EXPECT_CALL(*listener_, on_state_changed(FileLocatorFlow::State::RUNNING)).Times(1);
    flow->start();
    Mock::VerifyAndClearExpectations(listener_.get());

    EXPECT_CALL(*listener_, on_state_changed(FileLocatorFlow::State::STOPPING)).Times(1);
    EXPECT_CALL(*listener_, on_state_changed(FileLocatorFlow::State::IDLE)).Times(1);
}

TEST_F(FileLocatorFlowTest, InitiateSearch)
{
    const std::string file_hash = "manele2021";
    AHash             bin_file_hash;
    uint8_t           ttl = 3;
    std::generate(bin_file_hash.begin(), bin_file_hash.end(), [&] { return rng_.next<Byte>(); });
    std::vector<IPv4Address> peers(static_cast<size_t>(search_propagation_degree_));
    std::generate(peers.begin(), peers.end(), [&] { return rng_.next<IPv4Address>(); });

    auto flow = make_flow(ttl);
    flow->start();

    ON_CALL(*file_storage_, contains(file_hash)).WillByDefault(Return(false));
    ON_CALL(*file_hash_interpreter_, decode(file_hash, _))
        .WillByDefault(DoAll(SetArgReferee<1>(bin_file_hash), Return(true)));
    ON_CALL(*peer_address_provider_, get_peers(search_propagation_degree_, _))
        .WillByDefault(make_get_peers_action(peers));

    std::vector<IPv4Address> sent_to;
    std::vector<SearchId>    search_ids;

    EXPECT_CALL(*protocol_message_handler_,
        send(_, ResultOf([](auto &&ptr) { return ptr.get(); },
                    WhenDynamicCastTo<SearchMessage *>(
                        Pointee(AllOf(Field(&SearchMessage::sender_public_key, pub_key_),
                            Field(&SearchMessage::file_hash, bin_file_hash),
                            Field(&SearchMessage::time_to_live, ttl)))))))
        .Times(search_propagation_degree_)
        .WillRepeatedly(make_send_message_action(true, [&](auto p, auto m) {
            sent_to.push_back(p);
            search_ids.push_back(dynamic_cast<SearchMessage *>(m.get())->search_id);
        }));

    auto sh = flow->search(file_hash);
    EXPECT_TRUE(sh.is_valid());
    EXPECT_EQ(sh.data()->file_hash, file_hash);
    EXPECT_EQ(sh.data()->sender_public_key, pub_key_);

    thread_pool_->process_all_jobs();

    ASSERT_THAT(sent_to, UnorderedElementsAreArray(peers));
    ASSERT_THAT(search_ids, Each(sh.data()->search_id));
}

TEST_F(FileLocatorFlowTest, InitiateSearch_FlowNotRunning)
{
    const std::string file_hash = "manele2021";
    AHash             bin_file_hash;
    std::generate(bin_file_hash.begin(), bin_file_hash.end(), [&] { return rng_.next<Byte>(); });
    std::vector<IPv4Address> peers(static_cast<size_t>(search_propagation_degree_));
    std::generate(peers.begin(), peers.end(), [&] { return rng_.next<IPv4Address>(); });

    auto flow = make_flow();

    ON_CALL(*file_storage_, contains(file_hash)).WillByDefault(Return(false));
    ON_CALL(*file_hash_interpreter_, decode(file_hash, _))
        .WillByDefault(DoAll(SetArgReferee<1>(bin_file_hash), Return(true)));
    ON_CALL(*peer_address_provider_, get_peers(search_propagation_degree_, _))
        .WillByDefault(make_get_peers_action(peers));
    EXPECT_CALL(*protocol_message_handler_, send(_, _)).Times(0);

    auto sh = flow->search(file_hash);
    EXPECT_FALSE(sh.is_valid());

    thread_pool_->process_all_jobs();
}

TEST_F(FileLocatorFlowTest, InitiateSearch_FileAlreadyPresent)
{
    const std::string file_hash = "manele2021";
    AHash             bin_file_hash;
    std::generate(bin_file_hash.begin(), bin_file_hash.end(), [&] { return rng_.next<Byte>(); });
    std::vector<IPv4Address> peers(static_cast<size_t>(search_propagation_degree_));
    std::generate(peers.begin(), peers.end(), [&] { return rng_.next<IPv4Address>(); });

    auto flow = make_flow();
    flow->start();

    ON_CALL(*file_storage_, contains(file_hash)).WillByDefault(Return(true));
    ON_CALL(*file_hash_interpreter_, decode(file_hash, _))
        .WillByDefault(DoAll(SetArgReferee<1>(bin_file_hash), Return(true)));
    ON_CALL(*peer_address_provider_, get_peers(search_propagation_degree_, _))
        .WillByDefault(make_get_peers_action(peers));
    EXPECT_CALL(*protocol_message_handler_, send(_, _)).Times(0);

    auto sh = flow->search(file_hash);
    EXPECT_FALSE(sh.is_valid());

    thread_pool_->process_all_jobs();
}

TEST_F(FileLocatorFlowTest, InitiateSearch_InvalidFileHash)
{
    const std::string        file_hash = "manele2021";
    std::vector<IPv4Address> peers(static_cast<size_t>(search_propagation_degree_));
    std::generate(peers.begin(), peers.end(), [&] { return rng_.next<IPv4Address>(); });

    auto flow = make_flow();
    flow->start();

    ON_CALL(*file_storage_, contains(file_hash)).WillByDefault(Return(false));
    ON_CALL(*file_hash_interpreter_, decode(file_hash, _)).WillByDefault(Return(false));
    ON_CALL(*peer_address_provider_, get_peers(search_propagation_degree_, _))
        .WillByDefault(make_get_peers_action(peers));
    EXPECT_CALL(*protocol_message_handler_, send(_, _)).Times(0);

    auto sh = flow->search(file_hash);
    EXPECT_FALSE(sh.is_valid());

    thread_pool_->process_all_jobs();
}

TEST_F(FileLocatorFlowTest, ForwardSearch)
{
    const std::string file_hash = "manele2021";
    AHash             bin_file_hash;
    std::generate(bin_file_hash.begin(), bin_file_hash.end(), [&] { return rng_.next<Byte>(); });
    std::vector<IPv4Address> peers(static_cast<size_t>(search_propagation_degree_));
    std::generate(peers.begin(), peers.end(), [&] { return rng_.next<IPv4Address>(); });
    IPv4Address from = rng_.next<IPv4Address>();

    SearchMessage msg;
    msg.request_id        = rng_.next<RequestId>();
    msg.sender_public_key = "kkt";
    std::copy(bin_file_hash.cbegin(), bin_file_hash.cend(), msg.file_hash.begin());
    msg.search_id    = rng_.next<SearchId>();
    msg.time_to_live = 3;

    auto flow = make_flow();
    flow->start();

    ON_CALL(*file_storage_, contains(file_hash)).WillByDefault(Return(false));
    ON_CALL(*file_hash_interpreter_, encode(_)).WillByDefault(Return(file_hash));
    ON_CALL(*peer_address_provider_, get_peers(search_propagation_degree_, _))
        .WillByDefault(make_get_peers_action(peers));

    std::vector<IPv4Address> sent_to;

    EXPECT_CALL(*protocol_message_handler_,
        send(_, ResultOf([](auto &&ptr) { return ptr.get(); },
                    WhenDynamicCastTo<SearchMessage *>(Pointee(
                        AllOf(Field(&SearchMessage::sender_public_key, msg.sender_public_key),
                            Field(&SearchMessage::file_hash, msg.file_hash),
                            Field(&SearchMessage::request_id, Not(msg.request_id)),
                            Field(&SearchMessage::search_id, msg.search_id),
                            Field(&SearchMessage::time_to_live, msg.time_to_live - 1)))))))
        .Times(search_propagation_degree_)
        .WillRepeatedly(make_send_message_action(
            true, [&](IPv4Address p, auto /*msg*/) { sent_to.push_back(p); }));

    EXPECT_CALL(*protocol_message_handler_,
        send_reply(from, Pointee(AllOf(Field(&BasicReply::request_id, msg.request_id),
                             Field(&BasicReply::status_code, StatusCode::OK)))))
        .Times(1)
        .WillRepeatedly(make_send_reply_action());

    inbound_request_dispatcher_->on_message_received(from, msg);
    thread_pool_->process_all_jobs();

    ASSERT_THAT(sent_to, UnorderedElementsAreArray(peers));
}

TEST_F(FileLocatorFlowTest, ForwardSearch_PropagationLimit)
{
    const std::string file_hash = "manele2021";
    AHash             bin_file_hash;
    std::generate(bin_file_hash.begin(), bin_file_hash.end(), [&] { return rng_.next<Byte>(); });
    std::vector<IPv4Address> peers(static_cast<size_t>(search_propagation_degree_));
    IPv4Address              from = rng_.next<IPv4Address>();

    SearchMessage msg;
    msg.request_id        = rng_.next<RequestId>();
    msg.sender_public_key = "kkt";
    std::copy(bin_file_hash.cbegin(), bin_file_hash.cend(), msg.file_hash.begin());
    msg.search_id    = rng_.next<SearchId>();
    msg.time_to_live = 1;

    auto flow = make_flow();
    flow->start();

    ON_CALL(*file_storage_, contains(file_hash)).WillByDefault(Return(false));
    ON_CALL(*file_hash_interpreter_, encode(_)).WillByDefault(Return(file_hash));
    ON_CALL(*peer_address_provider_, get_peers(search_propagation_degree_, _))
        .WillByDefault(make_get_peers_action(peers));

    EXPECT_CALL(*protocol_message_handler_,
        send_reply(from, Pointee(AllOf(Field(&BasicReply::request_id, msg.request_id),
                             Field(&BasicReply::status_code, StatusCode::PROPAGATION_LIMIT)))))
        .Times(1)
        .WillRepeatedly(make_send_reply_action());

    inbound_request_dispatcher_->on_message_received(from, msg);
    thread_pool_->process_all_jobs();
}

TEST_F(FileLocatorFlowTest, ForwardSearch_PropagationLoop)
{
    const std::string file_hash = "manele2021";
    AHash             bin_file_hash;
    std::generate(bin_file_hash.begin(), bin_file_hash.end(), [&] { return rng_.next<Byte>(); });
    std::vector<IPv4Address> peers(static_cast<size_t>(search_propagation_degree_));
    std::generate(peers.begin(), peers.end(), [&] { return rng_.next<IPv4Address>(); });
    IPv4Address from  = rng_.next<IPv4Address>();
    IPv4Address from2 = rng_.next<IPv4Address>();

    SearchMessage msg;
    msg.request_id        = rng_.next<RequestId>();
    msg.sender_public_key = "kkt";
    std::copy(bin_file_hash.cbegin(), bin_file_hash.cend(), msg.file_hash.begin());
    msg.search_id    = rng_.next<SearchId>();
    msg.time_to_live = 3;

    auto flow = make_flow();
    flow->start();

    ON_CALL(*file_storage_, contains(file_hash)).WillByDefault(Return(false));
    ON_CALL(*file_hash_interpreter_, encode(_)).WillByDefault(Return(file_hash));
    ON_CALL(*peer_address_provider_, get_peers(search_propagation_degree_, _))
        .WillByDefault(make_get_peers_action(peers));

    std::vector<IPv4Address> sent_to;

    EXPECT_CALL(*protocol_message_handler_,
        send(_, ResultOf([](auto &&ptr) { return ptr.get(); },
                    WhenDynamicCastTo<SearchMessage *>(Pointee(
                        AllOf(Field(&SearchMessage::sender_public_key, msg.sender_public_key),
                            Field(&SearchMessage::file_hash, msg.file_hash),
                            Field(&SearchMessage::request_id, Not(msg.request_id)),
                            Field(&SearchMessage::search_id, msg.search_id)))))))
        .Times(search_propagation_degree_)
        .WillRepeatedly(make_send_message_action(
            true, [&](IPv4Address p, auto /*msg*/) { sent_to.push_back(p); }));

    EXPECT_CALL(*protocol_message_handler_,
        send_reply(from, Pointee(AllOf(Field(&BasicReply::request_id, msg.request_id),
                             Field(&BasicReply::status_code, StatusCode::OK)))))
        .Times(1)
        .WillRepeatedly(make_send_reply_action());

    inbound_request_dispatcher_->on_message_received(from, msg);
    thread_pool_->process_all_jobs();

    msg.request_id = rng_.next<RequestId>();
    inbound_request_dispatcher_->on_message_received(from2, msg);
    thread_pool_->process_all_jobs();

    ASSERT_THAT(sent_to, UnorderedElementsAreArray(peers));
}

TEST_F(FileLocatorFlowTest, ForwardSearch_NoPeers)
{
    const std::string file_hash = "manele2021";
    AHash             bin_file_hash;
    std::generate(bin_file_hash.begin(), bin_file_hash.end(), [&] { return rng_.next<Byte>(); });
    IPv4Address from = rng_.next<IPv4Address>();

    SearchMessage msg;
    msg.request_id        = rng_.next<RequestId>();
    msg.sender_public_key = "kkt";
    std::copy(bin_file_hash.cbegin(), bin_file_hash.cend(), msg.file_hash.begin());
    msg.search_id    = rng_.next<SearchId>();
    msg.time_to_live = 3;

    auto flow = make_flow();
    flow->start();

    ON_CALL(*file_storage_, contains(file_hash)).WillByDefault(Return(false));
    ON_CALL(*file_hash_interpreter_, encode(_)).WillByDefault(Return(file_hash));
    ON_CALL(*peer_address_provider_, get_peers(search_propagation_degree_, _))
        .WillByDefault(make_get_peers_action({}));

    EXPECT_CALL(*protocol_message_handler_,
        send_reply(from, Pointee(AllOf(Field(&BasicReply::request_id, msg.request_id),
                             Field(&BasicReply::status_code, StatusCode::CANNOT_FORWARD)))))
        .Times(1)
        .WillRepeatedly(make_send_reply_action());

    inbound_request_dispatcher_->on_message_received(from, msg);
    thread_pool_->process_all_jobs();
}

TEST_F(FileLocatorFlowTest, FileWanted)
{
    const std::string file_hash = "manele2021";
    AHash             bin_file_hash;
    std::generate(bin_file_hash.begin(), bin_file_hash.end(), [&] { return rng_.next<Byte>(); });
    IPv4Address from = rng_.next<IPv4Address>();

    SearchMessage msg;
    msg.request_id        = rng_.next<RequestId>();
    msg.sender_public_key = "kkt";
    std::copy(bin_file_hash.cbegin(), bin_file_hash.cend(), msg.file_hash.begin());
    msg.search_id    = rng_.next<SearchId>();
    msg.time_to_live = 3;

    auto flow = make_flow();
    flow->start();
    flow->register_listener(listener_);

    ON_CALL(*file_storage_, contains(file_hash)).WillByDefault(Return(true));
    ON_CALL(*file_hash_interpreter_, encode(_)).WillByDefault(Return(file_hash));

    std::vector<IPv4Address> sent_to;

    EXPECT_CALL(*protocol_message_handler_,
        send_reply(from, Pointee(AllOf(Field(&BasicReply::request_id, msg.request_id),
                             Field(&BasicReply::status_code, StatusCode::OK)))))
        .Times(1)
        .WillRepeatedly(make_send_reply_action());

    EXPECT_CALL(
        *listener_, on_file_wanted(ResultOf([](const auto &sh) { return sh.data(); },
                        Pointee(AllOf(Field(&SearchHandleImpl::search_id, msg.search_id),
                            Field(&SearchHandleImpl::file_hash, file_hash),
                            Field(&SearchHandleImpl::sender_public_key, msg.sender_public_key))))))
        .Times(1);

    inbound_request_dispatcher_->on_message_received(from, msg);
    thread_pool_->process_all_jobs();
}

TEST_F(FileLocatorFlowTest, SendOffer)
{
    const std::string file_hash = "manele2021";
    AHash             bin_file_hash;
    std::generate(bin_file_hash.begin(), bin_file_hash.end(), [&] { return rng_.next<Byte>(); });
    IPv4Address from = rng_.next<IPv4Address>();
    TransferKey transfer_key;
    std::generate(transfer_key.begin(), transfer_key.end(), [&] { return rng_.next<Byte>(); });
    std::vector<TransferHandleImpl::PartData> parts(3);
    std::generate(parts.begin(), parts.end(), [&] {
        return TransferHandleImpl::PartData {
            rng_.next<IPv4Address>(), rng_.next<FileSize>(), rng_.next<PartSize>()};
    });
    std::vector<Byte> encrypted_secret_data(666);
    std::generate(encrypted_secret_data.begin(), encrypted_secret_data.end(),
        [&] { return rng_.next<Byte>(); });

    SearchMessage msg;
    msg.request_id        = rng_.next<RequestId>();
    msg.sender_public_key = "kkt";
    std::copy(bin_file_hash.cbegin(), bin_file_hash.cend(), msg.file_hash.begin());
    msg.search_id    = rng_.next<SearchId>();
    msg.time_to_live = 3;

    auto flow = make_flow();
    flow->start();
    flow->register_listener(listener_);

    ON_CALL(*file_storage_, contains(file_hash)).WillByDefault(Return(true));
    ON_CALL(*file_hash_interpreter_, encode(_)).WillByDefault(Return(file_hash));

    std::vector<IPv4Address> sent_to;

    ON_CALL(*protocol_message_handler_,
        send_reply(from, Pointee(AllOf(Field(&BasicReply::request_id, msg.request_id),
                             Field(&BasicReply::status_code, StatusCode::OK)))))
        .WillByDefault(make_send_reply_action());

    SearchHandle search_handle;

    ON_CALL(
        *listener_, on_file_wanted(ResultOf([](const auto &sh) { return sh.data(); },
                        Pointee(AllOf(Field(&SearchHandleImpl::search_id, msg.search_id),
                            Field(&SearchHandleImpl::file_hash, file_hash),
                            Field(&SearchHandleImpl::sender_public_key, msg.sender_public_key))))))
        .WillByDefault(SaveArg<0>(&search_handle));

    inbound_request_dispatcher_->on_message_received(from, msg);
    thread_pool_->process_all_jobs();

    TransferHandle transfer_handle(std::make_shared<TransferHandleImpl>(
        *search_handle.data(), rng_.next<OfferId>(), transfer_key, parts));

    ON_CALL(*secret_data_interpreter_,
        encrypt_offer_message(AllOf(Field(&OfferMessage::SecretData::transfer_key, transfer_key),
                                  Truly([&](const auto &secret_data) {
                                      return std::equal(secret_data.parts.cbegin(),
                                          secret_data.parts.cend(), parts.cbegin(),
                                          [](const auto &p1, const auto &p2) {
                                              return p1.drop_point == p2.drop_point &&
                                                     p1.part_offset == p2.part_offset &&
                                                     p1.part_size == p2.part_size;
                                          });
                                  })),
            msg.sender_public_key))
        .WillByDefault(Return(encrypted_secret_data));

    EXPECT_CALL(*protocol_message_handler_,
        send(from, ResultOf([](auto &&ptr) { return ptr.get(); },
                       WhenDynamicCastTo<OfferMessage *>(
                           Pointee(AllOf(Field(&OfferMessage::search_id, msg.search_id),
                               Field(&OfferMessage::offer_id, transfer_handle.data()->offer_id),
                               Field(&OfferMessage::encrypted_data, encrypted_secret_data)))))))
        .Times(1)
        .WillRepeatedly(make_send_message_action(true));

    EXPECT_TRUE(flow->send_offer(transfer_handle));
    thread_pool_->process_all_jobs();
}

TEST_F(FileLocatorFlowTest, SendOffer_OfferIdDuplication)
{
    const std::string file_hash = "manele2021";
    AHash             bin_file_hash;
    std::generate(bin_file_hash.begin(), bin_file_hash.end(), [&] { return rng_.next<Byte>(); });
    IPv4Address from = rng_.next<IPv4Address>();
    TransferKey transfer_key;
    std::generate(transfer_key.begin(), transfer_key.end(), [&] { return rng_.next<Byte>(); });
    std::vector<TransferHandleImpl::PartData> parts(3);
    std::generate(parts.begin(), parts.end(), [&] {
        return TransferHandleImpl::PartData {
            rng_.next<IPv4Address>(), rng_.next<FileSize>(), rng_.next<PartSize>()};
    });
    std::vector<Byte> encrypted_secret_data(666);
    std::generate(encrypted_secret_data.begin(), encrypted_secret_data.end(),
        [&] { return rng_.next<Byte>(); });

    SearchMessage msg;
    msg.request_id        = rng_.next<RequestId>();
    msg.sender_public_key = "kkt";
    std::copy(bin_file_hash.cbegin(), bin_file_hash.cend(), msg.file_hash.begin());
    msg.search_id    = rng_.next<SearchId>();
    msg.time_to_live = 3;

    auto flow = make_flow();
    flow->start();
    flow->register_listener(listener_);

    ON_CALL(*file_storage_, contains(file_hash)).WillByDefault(Return(true));
    ON_CALL(*file_hash_interpreter_, encode(_)).WillByDefault(Return(file_hash));

    std::vector<IPv4Address> sent_to;

    ON_CALL(*protocol_message_handler_,
        send_reply(from, Pointee(AllOf(Field(&BasicReply::request_id, msg.request_id),
                             Field(&BasicReply::status_code, StatusCode::OK)))))
        .WillByDefault(make_send_reply_action());

    SearchHandle search_handle;

    ON_CALL(
        *listener_, on_file_wanted(ResultOf([](const auto &sh) { return sh.data(); },
                        Pointee(AllOf(Field(&SearchHandleImpl::search_id, msg.search_id),
                            Field(&SearchHandleImpl::file_hash, file_hash),
                            Field(&SearchHandleImpl::sender_public_key, msg.sender_public_key))))))
        .WillByDefault(SaveArg<0>(&search_handle));

    inbound_request_dispatcher_->on_message_received(from, msg);
    thread_pool_->process_all_jobs();

    TransferHandle transfer_handle(std::make_shared<TransferHandleImpl>(
        *search_handle.data(), rng_.next<OfferId>(), transfer_key, parts));

    ON_CALL(*secret_data_interpreter_,
        encrypt_offer_message(AllOf(Field(&OfferMessage::SecretData::transfer_key, transfer_key),
                                  Truly([&](const auto &secret_data) {
                                      return std::equal(secret_data.parts.cbegin(),
                                          secret_data.parts.cend(), parts.cbegin(),
                                          [](const auto &p1, const auto &p2) {
                                              return p1.drop_point == p2.drop_point &&
                                                     p1.part_offset == p2.part_offset &&
                                                     p1.part_size == p2.part_size;
                                          });
                                  })),
            msg.sender_public_key))
        .WillByDefault(Return(encrypted_secret_data));

    EXPECT_CALL(*protocol_message_handler_,
        send(from, ResultOf([](auto &&ptr) { return ptr.get(); },
                       WhenDynamicCastTo<OfferMessage *>(
                           Pointee(AllOf(Field(&OfferMessage::search_id, msg.search_id),
                               Field(&OfferMessage::offer_id, transfer_handle.data()->offer_id),
                               Field(&OfferMessage::encrypted_data, encrypted_secret_data)))))))
        .Times(1)
        .WillRepeatedly(make_send_message_action(true));

    EXPECT_TRUE(flow->send_offer(transfer_handle));
    thread_pool_->process_all_jobs();
    EXPECT_FALSE(flow->send_offer(transfer_handle));
}

TEST_F(FileLocatorFlowTest, SendOffer_NoAssociatedSearch)
{
    const std::string file_hash = "manele2021";
    IPv4Address       from      = rng_.next<IPv4Address>();
    TransferKey       transfer_key;
    std::generate(transfer_key.begin(), transfer_key.end(), [&] { return rng_.next<Byte>(); });
    std::vector<TransferHandleImpl::PartData> parts(3);
    std::generate(parts.begin(), parts.end(), [&] {
        return TransferHandleImpl::PartData {
            rng_.next<IPv4Address>(), rng_.next<FileSize>(), rng_.next<PartSize>()};
    });

    auto flow = make_flow();
    flow->start();
    flow->register_listener(listener_);

    std::vector<IPv4Address> sent_to;

    TransferHandle transfer_handle(std::make_shared<TransferHandleImpl>(
        SearchHandleImpl {file_hash, rng_.next<SearchId>(), "kkt"}, rng_.next<OfferId>(),
        transfer_key, parts));

    EXPECT_CALL(*protocol_message_handler_, send(from, _)).Times(0);

    EXPECT_FALSE(flow->send_offer(transfer_handle));
    thread_pool_->process_all_jobs();
}

TEST_F(FileLocatorFlowTest, ForwardOffer)
{
    const std::string file_hash = "manele2021";
    AHash             bin_file_hash;
    std::generate(bin_file_hash.begin(), bin_file_hash.end(), [&] { return rng_.next<Byte>(); });
    std::vector<IPv4Address> peers(static_cast<size_t>(search_propagation_degree_));
    std::generate(peers.begin(), peers.end(), [&] { return rng_.next<IPv4Address>(); });
    IPv4Address from = rng_.next<IPv4Address>();

    SearchMessage search_msg;
    search_msg.request_id        = rng_.next<RequestId>();
    search_msg.sender_public_key = "kkt";
    std::copy(bin_file_hash.cbegin(), bin_file_hash.cend(), search_msg.file_hash.begin());
    search_msg.search_id    = rng_.next<SearchId>();
    search_msg.time_to_live = 3;

    auto flow = make_flow();
    flow->start();

    ON_CALL(*file_storage_, contains(file_hash)).WillByDefault(Return(false));
    ON_CALL(*file_hash_interpreter_, encode(_)).WillByDefault(Return(file_hash));
    ON_CALL(*peer_address_provider_, get_peers(search_propagation_degree_, _))
        .WillByDefault(make_get_peers_action(peers));

    EXPECT_CALL(*protocol_message_handler_,
        send(_, ResultOf([](auto &&ptr) { return ptr.get(); },
                    WhenDynamicCastTo<SearchMessage *>(Pointee(AllOf(
                        Field(&SearchMessage::sender_public_key, search_msg.sender_public_key),
                        Field(&SearchMessage::file_hash, search_msg.file_hash),
                        Field(&SearchMessage::request_id, Not(search_msg.request_id)),
                        Field(&SearchMessage::search_id, search_msg.search_id)))))))
        .Times(search_propagation_degree_)
        .WillRepeatedly(make_send_message_action(true));

    EXPECT_CALL(*protocol_message_handler_,
        send_reply(from, Pointee(AllOf(Field(&BasicReply::request_id, search_msg.request_id),
                             Field(&BasicReply::status_code, StatusCode::OK)))))
        .Times(1)
        .WillRepeatedly(make_send_reply_action());

    inbound_request_dispatcher_->on_message_received(from, search_msg);
    thread_pool_->process_all_jobs();

    OfferMessage offer_msg;
    offer_msg.request_id = rng_.next<RequestId>();
    offer_msg.search_id  = search_msg.search_id;
    offer_msg.offer_id   = rng_.next<OfferId>();
    offer_msg.encrypted_data.resize(666);
    std::generate(offer_msg.encrypted_data.begin(), offer_msg.encrypted_data.end(),
        [&] { return rng_.next<Byte>(); });

    EXPECT_CALL(*protocol_message_handler_,
        send(from, ResultOf([](auto &&ptr) { return ptr.get(); },
                       WhenDynamicCastTo<OfferMessage *>(Pointee(
                           AllOf(Field(&OfferMessage::request_id, Not(offer_msg.request_id)),
                               Field(&OfferMessage::search_id, offer_msg.search_id),
                               Field(&OfferMessage::offer_id, offer_msg.offer_id),
                               Field(&OfferMessage::encrypted_data, offer_msg.encrypted_data)))))))
        .Times(1)
        .WillRepeatedly(make_send_message_action(true));

    EXPECT_CALL(*protocol_message_handler_,
        send_reply(peers[0], Pointee(AllOf(Field(&BasicReply::request_id, offer_msg.request_id),
                                 Field(&BasicReply::status_code, StatusCode::OK)))))
        .Times(1)
        .WillRepeatedly(make_send_reply_action());

    inbound_request_dispatcher_->on_message_received(peers[0], offer_msg);
    thread_pool_->process_all_jobs();
}

TEST_F(FileLocatorFlowTest, ForwardOffer_UnknownSearchId)
{
    IPv4Address from = rng_.next<IPv4Address>();

    auto flow = make_flow();
    flow->start();

    OfferMessage offer_msg;
    offer_msg.request_id = rng_.next<RequestId>();
    offer_msg.search_id  = rng_.next<SearchId>();
    offer_msg.offer_id   = rng_.next<OfferId>();
    offer_msg.encrypted_data.resize(666);
    std::generate(offer_msg.encrypted_data.begin(), offer_msg.encrypted_data.end(),
        [&] { return rng_.next<Byte>(); });

    EXPECT_CALL(*protocol_message_handler_, send(_, _)).Times(0);

    EXPECT_CALL(*protocol_message_handler_,
        send_reply(from, Pointee(AllOf(Field(&BasicReply::request_id, offer_msg.request_id),
                             Field(&BasicReply::status_code, StatusCode::CANNOT_FORWARD)))))
        .Times(1)
        .WillRepeatedly(make_send_reply_action());

    inbound_request_dispatcher_->on_message_received(from, offer_msg);
    thread_pool_->process_all_jobs();
}

TEST_F(FileLocatorFlowTest, FileFound)
{
    const std::string file_hash = "manele2021";
    AHash             bin_file_hash;
    std::generate(bin_file_hash.begin(), bin_file_hash.end(), [&] { return rng_.next<Byte>(); });
    std::vector<IPv4Address> peers(static_cast<size_t>(search_propagation_degree_));
    std::generate(peers.begin(), peers.end(), [&] { return rng_.next<IPv4Address>(); });

    auto flow = make_flow();
    flow->start();
    flow->register_listener(listener_);

    ON_CALL(*file_storage_, contains(file_hash)).WillByDefault(Return(false));
    ON_CALL(*file_hash_interpreter_, decode(file_hash, _))
        .WillByDefault(DoAll(SetArgReferee<1>(bin_file_hash), Return(true)));
    ON_CALL(*peer_address_provider_, get_peers(search_propagation_degree_, _))
        .WillByDefault(make_get_peers_action(peers));

    EXPECT_CALL(*protocol_message_handler_,
        send(_, ResultOf([](auto &&ptr) { return ptr.get(); },
                    WhenDynamicCastTo<SearchMessage *>(
                        Pointee(AllOf(Field(&SearchMessage::sender_public_key, pub_key_),
                            Field(&SearchMessage::file_hash, bin_file_hash)))))))
        .Times(search_propagation_degree_)
        .WillRepeatedly(make_send_message_action(true));

    auto sh = flow->search(file_hash);
    EXPECT_TRUE(sh.is_valid());
    EXPECT_EQ(sh.data()->file_hash, file_hash);
    EXPECT_EQ(sh.data()->sender_public_key, pub_key_);

    thread_pool_->process_all_jobs();

    OfferMessage offer_msg;
    offer_msg.request_id = rng_.next<RequestId>();
    offer_msg.search_id  = sh.data()->search_id;
    offer_msg.offer_id   = rng_.next<OfferId>();
    offer_msg.encrypted_data.resize(666);
    std::generate(offer_msg.encrypted_data.begin(), offer_msg.encrypted_data.end(),
        [&] { return rng_.next<Byte>(); });

    OfferMessage::SecretData secret_data;
    std::generate(secret_data.transfer_key.begin(), secret_data.transfer_key.end(),
        [&] { return rng_.next<Byte>(); });
    secret_data.parts.resize(3);
    std::generate(secret_data.parts.begin(), secret_data.parts.end(), [&] {
        return TransferHandleImpl::PartData {
            rng_.next<IPv4Address>(), rng_.next<FileSize>(), rng_.next<PartSize>()};
    });

    ON_CALL(*secret_data_interpreter_, decrypt_offer_message(offer_msg.encrypted_data, pri_key_))
        .WillByDefault(Return(std::make_pair(secret_data, true)));

    EXPECT_CALL(*protocol_message_handler_,
        send_reply(peers[0], Pointee(AllOf(Field(&BasicReply::request_id, offer_msg.request_id),
                                 Field(&BasicReply::status_code, StatusCode::OK)))))
        .Times(1)
        .WillRepeatedly(make_send_reply_action());

    EXPECT_CALL(*listener_,
        on_file_found(ResultOf([](const auto &th) { return th.data(); },
            Pointee(AllOf(
                Field(&TransferHandleImpl::search_handle,
                    AllOf(Field(&SearchHandleImpl::search_id, sh.data()->search_id),
                        Field(&SearchHandleImpl::file_hash, sh.data()->file_hash),
                        Field(&SearchHandleImpl::sender_public_key, sh.data()->sender_public_key))),
                Field(&TransferHandleImpl::offer_id, offer_msg.offer_id),
                Field(&TransferHandleImpl::transfer_key, secret_data.transfer_key),
                Field(&TransferHandleImpl::parts, Truly([&](const auto &parts) {
                    return std::equal(parts.cbegin(), parts.cend(), secret_data.parts.cbegin(),
                        [](const auto &p1, const auto &p2) {
                            return p1.drop_point == p2.drop_point &&
                                   p1.part_offset == p2.part_offset && p1.part_size == p2.part_size;
                        });
                })))))))
        .Times(1);

    inbound_request_dispatcher_->on_message_received(peers[0], offer_msg);
    thread_pool_->process_all_jobs();
}

TEST_F(FileLocatorFlowTest, FileFound_OfferDecryptionError)
{
    const std::string file_hash = "manele2021";
    AHash             bin_file_hash;
    std::generate(bin_file_hash.begin(), bin_file_hash.end(), [&] { return rng_.next<Byte>(); });
    std::vector<IPv4Address> peers(static_cast<size_t>(search_propagation_degree_));
    std::generate(peers.begin(), peers.end(), [&] { return rng_.next<IPv4Address>(); });

    auto flow = make_flow();
    flow->start();
    flow->register_listener(listener_);

    ON_CALL(*file_storage_, contains(file_hash)).WillByDefault(Return(false));
    ON_CALL(*file_hash_interpreter_, decode(file_hash, _))
        .WillByDefault(DoAll(SetArgReferee<1>(bin_file_hash), Return(true)));
    ON_CALL(*peer_address_provider_, get_peers(search_propagation_degree_, _))
        .WillByDefault(make_get_peers_action(peers));

    EXPECT_CALL(*protocol_message_handler_,
        send(_, ResultOf([](auto &&ptr) { return ptr.get(); },
                    WhenDynamicCastTo<SearchMessage *>(
                        Pointee(AllOf(Field(&SearchMessage::sender_public_key, pub_key_),
                            Field(&SearchMessage::file_hash, bin_file_hash)))))))
        .Times(search_propagation_degree_)
        .WillRepeatedly(make_send_message_action(true));

    auto sh = flow->search(file_hash);
    EXPECT_TRUE(sh.is_valid());
    EXPECT_EQ(sh.data()->file_hash, file_hash);
    EXPECT_EQ(sh.data()->sender_public_key, pub_key_);

    thread_pool_->process_all_jobs();

    OfferMessage offer_msg;
    offer_msg.request_id = rng_.next<RequestId>();
    offer_msg.search_id  = sh.data()->search_id;
    offer_msg.offer_id   = rng_.next<OfferId>();
    offer_msg.encrypted_data.resize(666);
    std::generate(offer_msg.encrypted_data.begin(), offer_msg.encrypted_data.end(),
        [&] { return rng_.next<Byte>(); });

    ON_CALL(*secret_data_interpreter_, decrypt_offer_message(offer_msg.encrypted_data, pri_key_))
        .WillByDefault(Return(std::make_pair(OfferMessage::SecretData {}, false)));

    EXPECT_CALL(*protocol_message_handler_,
        send_reply(peers[0], Pointee(AllOf(Field(&BasicReply::request_id, offer_msg.request_id),
                                 Field(&BasicReply::status_code, StatusCode::CANNOT_FORWARD)))))
        .Times(1)
        .WillRepeatedly(make_send_reply_action());

    EXPECT_CALL(*listener_, on_file_found(_)).Times(0);

    inbound_request_dispatcher_->on_message_received(peers[0], offer_msg);
    thread_pool_->process_all_jobs();
}

TEST_F(FileLocatorFlowTest, ConfirmTransfer)
{
    const std::string file_hash = "manele2021";
    AHash             bin_file_hash;
    std::generate(bin_file_hash.begin(), bin_file_hash.end(), [&] { return rng_.next<Byte>(); });
    std::vector<IPv4Address> peers(static_cast<size_t>(search_propagation_degree_));
    std::generate(peers.begin(), peers.end(), [&] { return rng_.next<IPv4Address>(); });

    auto flow = make_flow();
    flow->start();
    flow->register_listener(listener_);

    ON_CALL(*file_storage_, contains(file_hash)).WillByDefault(Return(false));
    ON_CALL(*file_hash_interpreter_, decode(file_hash, _))
        .WillByDefault(DoAll(SetArgReferee<1>(bin_file_hash), Return(true)));
    ON_CALL(*peer_address_provider_, get_peers(search_propagation_degree_, _))
        .WillByDefault(make_get_peers_action(peers));

    EXPECT_CALL(*protocol_message_handler_,
        send(_, ResultOf([](auto &&ptr) { return ptr.get(); },
                    WhenDynamicCastTo<SearchMessage *>(
                        Pointee(AllOf(Field(&SearchMessage::sender_public_key, pub_key_),
                            Field(&SearchMessage::file_hash, bin_file_hash)))))))
        .Times(search_propagation_degree_)
        .WillRepeatedly(make_send_message_action(true));

    auto sh = flow->search(file_hash);
    EXPECT_TRUE(sh.is_valid());
    EXPECT_EQ(sh.data()->file_hash, file_hash);
    EXPECT_EQ(sh.data()->sender_public_key, pub_key_);

    thread_pool_->process_all_jobs();

    OfferMessage offer_msg;
    offer_msg.request_id = rng_.next<RequestId>();
    offer_msg.search_id  = sh.data()->search_id;
    offer_msg.offer_id   = rng_.next<OfferId>();
    offer_msg.encrypted_data.resize(666);
    std::generate(offer_msg.encrypted_data.begin(), offer_msg.encrypted_data.end(),
        [&] { return rng_.next<Byte>(); });

    OfferMessage::SecretData secret_data;
    std::generate(secret_data.transfer_key.begin(), secret_data.transfer_key.end(),
        [&] { return rng_.next<Byte>(); });
    secret_data.parts.resize(3);
    std::generate(secret_data.parts.begin(), secret_data.parts.end(), [&] {
        return TransferHandleImpl::PartData {
            rng_.next<IPv4Address>(), rng_.next<FileSize>(), rng_.next<PartSize>()};
    });

    ON_CALL(*secret_data_interpreter_, decrypt_offer_message(offer_msg.encrypted_data, pri_key_))
        .WillByDefault(Return(std::make_pair(secret_data, true)));

    EXPECT_CALL(*protocol_message_handler_,
        send_reply(peers[0], Pointee(AllOf(Field(&BasicReply::request_id, offer_msg.request_id),
                                 Field(&BasicReply::status_code, StatusCode::OK)))))
        .Times(1)
        .WillRepeatedly(make_send_reply_action());

    TransferHandle transfer_handle;

    EXPECT_CALL(*listener_,
        on_file_found(ResultOf([](const auto &th) { return th.data(); },
            Pointee(AllOf(
                Field(&TransferHandleImpl::search_handle,
                    AllOf(Field(&SearchHandleImpl::search_id, sh.data()->search_id),
                        Field(&SearchHandleImpl::file_hash, sh.data()->file_hash),
                        Field(&SearchHandleImpl::sender_public_key, sh.data()->sender_public_key))),
                Field(&TransferHandleImpl::offer_id, offer_msg.offer_id),
                Field(&TransferHandleImpl::transfer_key, secret_data.transfer_key),
                Field(&TransferHandleImpl::parts, Truly([&](const auto &parts) {
                    return std::equal(parts.cbegin(), parts.cend(), secret_data.parts.cbegin(),
                        [](const auto &p1, const auto &p2) {
                            return p1.drop_point == p2.drop_point &&
                                   p1.part_offset == p2.part_offset && p1.part_size == p2.part_size;
                        });
                })))))))
        .Times(1)
        .WillRepeatedly(SaveArg<0>(&transfer_handle));

    inbound_request_dispatcher_->on_message_received(peers[0], offer_msg);
    thread_pool_->process_all_jobs();

    EXPECT_CALL(*protocol_message_handler_,
        send(peers[0],
            ResultOf([](auto &&ptr) { return ptr.get(); },
                WhenDynamicCastTo<ConfirmTransferMessage *>(Pointee(
                    Field(&ConfirmTransferMessage::offer_id, transfer_handle.data()->offer_id))))))
        .Times(1)
        .WillRepeatedly(make_send_message_action(true));

    flow->confirm_transfer(transfer_handle);
    thread_pool_->process_all_jobs();
}

TEST_F(FileLocatorFlowTest, ConfirmTransfer_UnknownOfferId)
{
    const std::string file_hash = "manele2021";
    AHash             bin_file_hash;
    std::generate(bin_file_hash.begin(), bin_file_hash.end(), [&] { return rng_.next<Byte>(); });
    std::vector<IPv4Address> peers(static_cast<size_t>(search_propagation_degree_));
    std::generate(peers.begin(), peers.end(), [&] { return rng_.next<IPv4Address>(); });

    auto flow = make_flow();
    flow->start();
    flow->register_listener(listener_);

    ON_CALL(*file_storage_, contains(file_hash)).WillByDefault(Return(false));
    ON_CALL(*file_hash_interpreter_, decode(file_hash, _))
        .WillByDefault(DoAll(SetArgReferee<1>(bin_file_hash), Return(true)));
    ON_CALL(*peer_address_provider_, get_peers(search_propagation_degree_, _))
        .WillByDefault(make_get_peers_action(peers));

    EXPECT_CALL(*protocol_message_handler_,
        send(_, ResultOf([](auto &&ptr) { return ptr.get(); },
                    WhenDynamicCastTo<SearchMessage *>(
                        Pointee(AllOf(Field(&SearchMessage::sender_public_key, pub_key_),
                            Field(&SearchMessage::file_hash, bin_file_hash)))))))
        .Times(search_propagation_degree_)
        .WillRepeatedly(make_send_message_action(true));

    auto sh = flow->search(file_hash);
    EXPECT_TRUE(sh.is_valid());
    EXPECT_EQ(sh.data()->file_hash, file_hash);
    EXPECT_EQ(sh.data()->sender_public_key, pub_key_);

    thread_pool_->process_all_jobs();

    TransferHandle transfer_handle {std::make_shared<TransferHandleImpl>(*sh.data(),
        rng_.next<OfferId>(), TransferKey {}, std::vector<TransferHandleImpl::PartData> {})};
    std::generate(transfer_handle.data()->transfer_key.begin(),
        transfer_handle.data()->transfer_key.end(), [&] { return rng_.next<Byte>(); });
    transfer_handle.data()->parts.resize(3);
    std::generate(transfer_handle.data()->parts.begin(), transfer_handle.data()->parts.end(), [&] {
        return TransferHandleImpl::PartData {
            rng_.next<IPv4Address>(), rng_.next<FileSize>(), rng_.next<PartSize>()};
    });

    EXPECT_CALL(*protocol_message_handler_,
        send(_,
            Pointee(Field(&::sand::protocol::Message::message_code, MessageCode::CONFIRMTRANSFER))))
        .Times(0);

    flow->confirm_transfer(transfer_handle);
    thread_pool_->process_all_jobs();
}

TEST_F(FileLocatorFlowTest, ForwardConfirmTransfer)
{
    const std::string file_hash = "manele2021";
    AHash             bin_file_hash;
    std::generate(bin_file_hash.begin(), bin_file_hash.end(), [&] { return rng_.next<Byte>(); });
    std::vector<IPv4Address> peers(static_cast<size_t>(search_propagation_degree_));
    std::generate(peers.begin(), peers.end(), [&] { return rng_.next<IPv4Address>(); });
    IPv4Address from = rng_.next<IPv4Address>();

    SearchMessage search_msg;
    search_msg.request_id        = rng_.next<RequestId>();
    search_msg.sender_public_key = "kkt";
    std::copy(bin_file_hash.cbegin(), bin_file_hash.cend(), search_msg.file_hash.begin());
    search_msg.search_id    = rng_.next<SearchId>();
    search_msg.time_to_live = 3;

    auto flow = make_flow();
    flow->start();

    ON_CALL(*file_storage_, contains(file_hash)).WillByDefault(Return(false));
    ON_CALL(*file_hash_interpreter_, encode(_)).WillByDefault(Return(file_hash));
    ON_CALL(*peer_address_provider_, get_peers(search_propagation_degree_, _))
        .WillByDefault(make_get_peers_action(peers));

    EXPECT_CALL(*protocol_message_handler_,
        send(_, ResultOf([](auto &&ptr) { return ptr.get(); },
                    WhenDynamicCastTo<SearchMessage *>(Pointee(AllOf(
                        Field(&SearchMessage::sender_public_key, search_msg.sender_public_key),
                        Field(&SearchMessage::file_hash, search_msg.file_hash),
                        Field(&SearchMessage::request_id, Not(search_msg.request_id)),
                        Field(&SearchMessage::search_id, search_msg.search_id)))))))
        .Times(search_propagation_degree_)
        .WillRepeatedly(make_send_message_action(true));

    EXPECT_CALL(*protocol_message_handler_,
        send_reply(from, Pointee(AllOf(Field(&BasicReply::request_id, search_msg.request_id),
                             Field(&BasicReply::status_code, StatusCode::OK)))))
        .Times(1)
        .WillRepeatedly(make_send_reply_action());

    inbound_request_dispatcher_->on_message_received(from, search_msg);
    thread_pool_->process_all_jobs();

    OfferMessage offer_msg;
    offer_msg.request_id = rng_.next<RequestId>();
    offer_msg.search_id  = search_msg.search_id;
    offer_msg.offer_id   = rng_.next<OfferId>();
    offer_msg.encrypted_data.resize(666);
    std::generate(offer_msg.encrypted_data.begin(), offer_msg.encrypted_data.end(),
        [&] { return rng_.next<Byte>(); });

    EXPECT_CALL(*protocol_message_handler_,
        send(from, ResultOf([](auto &&ptr) { return ptr.get(); },
                       WhenDynamicCastTo<OfferMessage *>(Pointee(
                           AllOf(Field(&OfferMessage::request_id, Not(offer_msg.request_id)),
                               Field(&OfferMessage::search_id, offer_msg.search_id),
                               Field(&OfferMessage::offer_id, offer_msg.offer_id),
                               Field(&OfferMessage::encrypted_data, offer_msg.encrypted_data)))))))
        .Times(1)
        .WillRepeatedly(make_send_message_action(true));

    EXPECT_CALL(*protocol_message_handler_,
        send_reply(peers[0], Pointee(AllOf(Field(&BasicReply::request_id, offer_msg.request_id),
                                 Field(&BasicReply::status_code, StatusCode::OK)))))
        .Times(1)
        .WillRepeatedly(make_send_reply_action());

    inbound_request_dispatcher_->on_message_received(peers[0], offer_msg);
    thread_pool_->process_all_jobs();

    ConfirmTransferMessage confirm_tx_msg;
    confirm_tx_msg.request_id = rng_.next<RequestId>();
    confirm_tx_msg.offer_id   = offer_msg.offer_id;

    EXPECT_CALL(*protocol_message_handler_,
        send(peers[0],
            ResultOf([](auto &&ptr) { return ptr.get(); },
                WhenDynamicCastTo<ConfirmTransferMessage *>(Pointee(AllOf(
                    Field(&ConfirmTransferMessage::request_id, Not(confirm_tx_msg.request_id)),
                    Field(&ConfirmTransferMessage::offer_id, confirm_tx_msg.offer_id)))))))
        .Times(1)
        .WillRepeatedly(make_send_message_action(true));

    EXPECT_CALL(*protocol_message_handler_,
        send_reply(from, Pointee(AllOf(Field(&BasicReply::request_id, confirm_tx_msg.request_id),
                             Field(&BasicReply::status_code, StatusCode::OK)))))
        .Times(1)
        .WillRepeatedly(make_send_reply_action());

    inbound_request_dispatcher_->on_message_received(from, confirm_tx_msg);
    thread_pool_->process_all_jobs();
}

TEST_F(FileLocatorFlowTest, ForwardConfirmTransfer_UnknownOfferId)
{
    IPv4Address from = rng_.next<IPv4Address>();

    auto flow = make_flow();
    flow->start();

    ConfirmTransferMessage msg;
    msg.request_id = rng_.next<RequestId>();
    msg.offer_id   = rng_.next<OfferId>();

    EXPECT_CALL(*protocol_message_handler_, send(_, _)).Times(0);
    EXPECT_CALL(*protocol_message_handler_,
        send_reply(from, Pointee(AllOf(Field(&BasicReply::request_id, msg.request_id),
                             Field(&BasicReply::status_code, StatusCode::CANNOT_FORWARD)))))
        .Times(1)
        .WillRepeatedly(make_send_reply_action());

    inbound_request_dispatcher_->on_message_received(from, msg);
    thread_pool_->process_all_jobs();
}

TEST_F(FileLocatorFlowTest, TransferConfirmed)
{
    const std::string file_hash = "manele2021";
    AHash             bin_file_hash;
    std::generate(bin_file_hash.begin(), bin_file_hash.end(), [&] { return rng_.next<Byte>(); });
    IPv4Address from = rng_.next<IPv4Address>();
    TransferKey transfer_key;
    std::generate(transfer_key.begin(), transfer_key.end(), [&] { return rng_.next<Byte>(); });
    std::vector<TransferHandleImpl::PartData> parts(3);
    std::generate(parts.begin(), parts.end(), [&] {
        return TransferHandleImpl::PartData {
            rng_.next<IPv4Address>(), rng_.next<FileSize>(), rng_.next<PartSize>()};
    });
    std::vector<Byte> encrypted_secret_data(666);
    std::generate(encrypted_secret_data.begin(), encrypted_secret_data.end(),
        [&] { return rng_.next<Byte>(); });

    SearchMessage msg;
    msg.request_id        = rng_.next<RequestId>();
    msg.sender_public_key = "kkt";
    std::copy(bin_file_hash.cbegin(), bin_file_hash.cend(), msg.file_hash.begin());
    msg.search_id    = rng_.next<SearchId>();
    msg.time_to_live = 3;

    auto flow = make_flow();
    flow->start();
    flow->register_listener(listener_);

    ON_CALL(*file_storage_, contains(file_hash)).WillByDefault(Return(true));
    ON_CALL(*file_hash_interpreter_, encode(_)).WillByDefault(Return(file_hash));

    std::vector<IPv4Address> sent_to;

    ON_CALL(*protocol_message_handler_,
        send_reply(from, Pointee(AllOf(Field(&BasicReply::request_id, msg.request_id),
                             Field(&BasicReply::status_code, StatusCode::OK)))))
        .WillByDefault(make_send_reply_action());

    SearchHandle search_handle;

    ON_CALL(
        *listener_, on_file_wanted(ResultOf([](const auto &sh) { return sh.data(); },
                        Pointee(AllOf(Field(&SearchHandleImpl::search_id, msg.search_id),
                            Field(&SearchHandleImpl::file_hash, file_hash),
                            Field(&SearchHandleImpl::sender_public_key, msg.sender_public_key))))))
        .WillByDefault(SaveArg<0>(&search_handle));

    inbound_request_dispatcher_->on_message_received(from, msg);
    thread_pool_->process_all_jobs();

    TransferHandle transfer_handle(std::make_shared<TransferHandleImpl>(
        *search_handle.data(), rng_.next<OfferId>(), transfer_key, parts));

    ON_CALL(*secret_data_interpreter_,
        encrypt_offer_message(AllOf(Field(&OfferMessage::SecretData::transfer_key, transfer_key),
                                  Truly([&](const auto &secret_data) {
                                      return std::equal(secret_data.parts.cbegin(),
                                          secret_data.parts.cend(), parts.cbegin(),
                                          [](const auto &p1, const auto &p2) {
                                              return p1.drop_point == p2.drop_point &&
                                                     p1.part_offset == p2.part_offset &&
                                                     p1.part_size == p2.part_size;
                                          });
                                  })),
            msg.sender_public_key))
        .WillByDefault(Return(encrypted_secret_data));

    EXPECT_CALL(*protocol_message_handler_,
        send(from, ResultOf([](auto &&ptr) { return ptr.get(); },
                       WhenDynamicCastTo<OfferMessage *>(
                           Pointee(AllOf(Field(&OfferMessage::search_id, msg.search_id),
                               Field(&OfferMessage::offer_id, transfer_handle.data()->offer_id),
                               Field(&OfferMessage::encrypted_data, encrypted_secret_data)))))))
        .Times(1)
        .WillRepeatedly(make_send_message_action(true));

    EXPECT_TRUE(flow->send_offer(transfer_handle));
    thread_pool_->process_all_jobs();

    ConfirmTransferMessage confirm_tx_msg;
    confirm_tx_msg.request_id = rng_.next<RequestId>();
    confirm_tx_msg.offer_id   = transfer_handle.data()->offer_id;

    EXPECT_CALL(*protocol_message_handler_,
        send_reply(from, Pointee(AllOf(Field(&BasicReply::request_id, confirm_tx_msg.request_id),
                             Field(&BasicReply::status_code, StatusCode::OK)))))
        .Times(1)
        .WillRepeatedly(make_send_reply_action());

    EXPECT_CALL(*listener_,
        on_transfer_confirmed(ResultOf([](const auto &th) { return th.data(); },
            Pointee(AllOf(Field(&TransferHandleImpl::search_handle,
                              AllOf(Field(&SearchHandleImpl::search_id,
                                        transfer_handle.data()->search_handle.search_id),
                                  Field(&SearchHandleImpl::file_hash,
                                      transfer_handle.data()->search_handle.file_hash),
                                  Field(&SearchHandleImpl::sender_public_key,
                                      transfer_handle.data()->search_handle.sender_public_key))),
                Field(&TransferHandleImpl::offer_id, transfer_handle.data()->offer_id),
                Field(&TransferHandleImpl::transfer_key, transfer_handle.data()->transfer_key),
                Field(&TransferHandleImpl::parts, Truly([&](const auto &parts) {
                    return std::equal(parts.cbegin(), parts.cend(),
                        transfer_handle.data()->parts.cbegin(), [](const auto &p1, const auto &p2) {
                            return p1.drop_point == p2.drop_point &&
                                   p1.part_offset == p2.part_offset && p1.part_size == p2.part_size;
                        });
                })))))))
        .Times(1);

    inbound_request_dispatcher_->on_message_received(from, confirm_tx_msg);
    thread_pool_->process_all_jobs();
}
