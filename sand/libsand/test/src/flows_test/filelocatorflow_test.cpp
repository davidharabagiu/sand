#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <future>
#include <memory>
#include <vector>

#include "filelocatorflowimpl.hpp"
#include "inboundrequestdispatcher.hpp"
#include "iothreadpool.hpp"
#include "random.hpp"
#include "searchhandleimpl.hpp"
#include "threadpool.hpp"

#include "filehashcalculator_mock.hpp"
#include "filelocatorflowlistener_mock.hpp"
#include "filestorage_mock.hpp"
#include "peeraddressprovider_mock.hpp"
#include "protocolmessagehandler_mock.hpp"
#include "secretdatainterpreter_mock.hpp"

using namespace ::sand::flows;
using namespace ::sand::utils;
using namespace ::sand::protocol;
using namespace ::sand::storage;
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
        file_hash_calculator_    = new NiceMock<FileHashCalculatorMock>();
        secret_data_interpreter_ = std::make_shared<NiceMock<SecretDataInterpreterMock>>();
        thread_pool_             = std::make_shared<ThreadPool>();
        listener_                = std::make_shared<NiceMock<FileLocatorFlowListenerMock>>();
    }

    std::unique_ptr<FileLocatorFlow> make_flow(
        int search_timeout_sec = 0, int routing_table_entry_expiration_time_sec = 0)
    {
        return std::make_unique<FileLocatorFlowImpl>(protocol_message_handler_,
            inbound_request_dispatcher_, peer_address_provider_, file_storage_,
            std::unique_ptr<FileHashCalculator>(file_hash_calculator_), secret_data_interpreter_,
            thread_pool_, thread_pool_, pub_key_, pri_key_, search_propagation_degree_,
            search_timeout_sec, routing_table_entry_expiration_time_sec);
    }

    static auto make_get_peers_action(const std::vector<IPv4Address> &peers)
    {
        return [=](int /*count*/) {
            std::promise<std::vector<IPv4Address>> promise;
            promise.set_value(peers);
            return promise.get_future();
        };
    }

    static auto make_send_search_action(bool                                         success,
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
    FileHashCalculatorMock *                     file_hash_calculator_;
    std::shared_ptr<SecretDataInterpreterMock>   secret_data_interpreter_;
    std::shared_ptr<Executer>                    thread_pool_;
    std::shared_ptr<FileLocatorFlowListenerMock> listener_;
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
    std::generate(bin_file_hash.begin(), bin_file_hash.end(), [&] { return rng_.next<Byte>(); });
    std::vector<IPv4Address> peers(static_cast<size_t>(search_propagation_degree_));
    std::generate(peers.begin(), peers.end(), [&] { return rng_.next<IPv4Address>(); });

    auto flow = make_flow();
    flow->start();

    ON_CALL(*file_storage_, contains(file_hash)).WillByDefault(Return(false));
    ON_CALL(*file_hash_calculator_, decode(file_hash, _))
        .WillByDefault(
            DoAll(SetArrayArgument<1>(bin_file_hash.cbegin(), bin_file_hash.cend()), Return(true)));
    ON_CALL(*peer_address_provider_, get_peers(search_propagation_degree_))
        .WillByDefault(make_get_peers_action(peers));

    std::vector<IPv4Address> sent_to;
    std::vector<SearchId>    search_ids;

    EXPECT_CALL(*protocol_message_handler_,
        send(_, ResultOf([](auto &&ptr) { return ptr.get(); },
                    WhenDynamicCastTo<SearchMessage *>(
                        Pointee(AllOf(Field(&SearchMessage::sender_public_key, pub_key_),
                            Field(&SearchMessage::file_hash, bin_file_hash)))))))
        .Times(search_propagation_degree_)
        .WillRepeatedly(make_send_search_action(true, [&](auto p, auto m) {
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
    ON_CALL(*file_hash_calculator_, decode(file_hash, _))
        .WillByDefault(
            DoAll(SetArrayArgument<1>(bin_file_hash.cbegin(), bin_file_hash.cend()), Return(true)));
    ON_CALL(*peer_address_provider_, get_peers(search_propagation_degree_))
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
    ON_CALL(*file_hash_calculator_, decode(file_hash, _))
        .WillByDefault(
            DoAll(SetArrayArgument<1>(bin_file_hash.cbegin(), bin_file_hash.cend()), Return(true)));
    ON_CALL(*peer_address_provider_, get_peers(search_propagation_degree_))
        .WillByDefault(make_get_peers_action(peers));
    EXPECT_CALL(*protocol_message_handler_, send(_, _)).Times(0);

    auto sh = flow->search(file_hash);
    EXPECT_FALSE(sh.is_valid());

    thread_pool_->process_all_jobs();
}

TEST_F(FileLocatorFlowTest, InitiateSearch_InvalidFileHash)
{
    const std::string file_hash = "manele2021";
    AHash             bin_file_hash;
    std::generate(bin_file_hash.begin(), bin_file_hash.end(), [&] { return rng_.next<Byte>(); });
    std::vector<IPv4Address> peers(static_cast<size_t>(search_propagation_degree_));
    std::generate(peers.begin(), peers.end(), [&] { return rng_.next<IPv4Address>(); });

    auto flow = make_flow();
    flow->start();

    ON_CALL(*file_storage_, contains(file_hash)).WillByDefault(Return(false));
    ON_CALL(*file_hash_calculator_, decode(file_hash, _)).WillByDefault(Return(false));
    ON_CALL(*peer_address_provider_, get_peers(search_propagation_degree_))
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
    msg.search_id = rng_.next<SearchId>();

    auto flow = make_flow();
    flow->start();

    ON_CALL(*file_storage_, contains(file_hash)).WillByDefault(Return(false));
    ON_CALL(*file_hash_calculator_, encode(_)).WillByDefault(Return(file_hash));
    ON_CALL(*peer_address_provider_, get_peers(search_propagation_degree_))
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
        .WillRepeatedly(make_send_search_action(
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
    msg.search_id = rng_.next<SearchId>();

    auto flow = make_flow();
    flow->start();

    ON_CALL(*file_storage_, contains(file_hash)).WillByDefault(Return(false));
    ON_CALL(*file_hash_calculator_, encode(_)).WillByDefault(Return(file_hash));
    ON_CALL(*peer_address_provider_, get_peers(search_propagation_degree_))
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
        .WillRepeatedly(make_send_search_action(
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
    msg.search_id = rng_.next<SearchId>();

    auto flow = make_flow();
    flow->start();

    ON_CALL(*file_storage_, contains(file_hash)).WillByDefault(Return(false));
    ON_CALL(*file_hash_calculator_, encode(_)).WillByDefault(Return(file_hash));
    ON_CALL(*peer_address_provider_, get_peers(search_propagation_degree_))
        .WillByDefault(make_get_peers_action({}));

    std::vector<IPv4Address> sent_to;

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
    msg.search_id = rng_.next<SearchId>();

    auto flow = make_flow();
    flow->start();
    flow->register_listener(listener_);

    ON_CALL(*file_storage_, contains(file_hash)).WillByDefault(Return(true));
    ON_CALL(*file_hash_calculator_, encode(_)).WillByDefault(Return(file_hash));

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
}

TEST_F(FileLocatorFlowTest, ForwardOffer)
{
}

TEST_F(FileLocatorFlowTest, FileFound)
{
}

TEST_F(FileLocatorFlowTest, ConfirmTransfer)
{
}

TEST_F(FileLocatorFlowTest, ForwardConfirmTransfer)
{
}

TEST_F(FileLocatorFlowTest, TransferConfirmed)
{
}
