#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <memory>

#include "filetransferflowimpl.hpp"
#include "inboundrequestdispatcher.hpp"
#include "random.hpp"
#include "searchhandleimpl.hpp"
#include "threadpool.hpp"
#include "transferhandleimpl.hpp"

#include "aescipher_mock.hpp"
#include "filehashinterpreter_mock.hpp"
#include "filestorage_mock.hpp"
#include "filetransferflowlistener_mock.hpp"
#include "peeraddressprovider_mock.hpp"
#include "protocolmessagehandler_mock.hpp"
#include "temporarydatastorage_mock.hpp"

using namespace ::testing;
using namespace ::sand::flows;
using namespace ::sand::protocol;
using namespace ::sand::network;
using namespace ::sand::crypto;
using namespace ::sand::utils;
using namespace ::sand::storage;

namespace
{
class FileTransferFlowTest : public Test
{
protected:
    void SetUp() override
    {
        protocol_message_handler_ = std::make_shared<NiceMock<ProtocolMessageHandlerMock>>();
        inbound_request_dispatcher_ =
            std::make_shared<InboundRequestDispatcher>(protocol_message_handler_);
        peer_address_provider_  = std::make_shared<NiceMock<PeerAddressProviderMock>>();
        file_storage_           = std::make_shared<NiceMock<FileStorageMock>>();
        file_hash_interpreter_  = new NiceMock<FileHashInterpreterMock>();
        temporary_data_storage_ = std::make_shared<NiceMock<TemporaryDataStorageMock>>();
        aes_                    = std::make_shared<NiceMock<AESCipherMock>>();
        thread_pool_            = std::make_shared<ThreadPool>();
        listener_               = std::make_shared<NiceMock<FileTransferFlowListenerMock>>();
    }

    std::unique_ptr<FileTransferFlow> make_flow(int receive_file_timeout = 0,
        int drop_point_request_timeout = 0, int lift_proxy_request_timeout = 0,
        int drop_point_transfer_timeout = 0, int lift_proxy_transfer_timeout = 0)
    {
        return std::make_unique<FileTransferFlowImpl>(protocol_message_handler_,
            inbound_request_dispatcher_, peer_address_provider_, file_storage_,
            std::unique_ptr<FileHashInterpreter>(file_hash_interpreter_), temporary_data_storage_,
            aes_, thread_pool_, thread_pool_, max_part_size_, max_chunk_size_,
            max_temp_storage_size_, receive_file_timeout, drop_point_request_timeout,
            lift_proxy_request_timeout, drop_point_transfer_timeout, lift_proxy_transfer_timeout);
    }

    static auto make_get_peers_action(const std::vector<IPv4Address> &peers)
    {
        return [=](int /*count*/, const std::set<IPv4Address> & /*exclude*/) {
            std::promise<std::vector<IPv4Address>> promise;
            promise.set_value(peers);
            return promise.get_future();
        };
    }

    static auto make_send_message_action(StatusCode                                  status_code,
        std::function<void(IPv4Address, std::unique_ptr<sand::protocol::Message>)> &&also_do_this =
            {})
    {
        return [=](IPv4Address addr, std::unique_ptr<sand::protocol::Message> msg) {
            auto reply         = std::make_unique<BasicReply>(msg->message_code);
            reply->request_id  = msg->request_id;
            reply->status_code = status_code;
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

    static std::vector<uint8_t> xor_encrypt(const std::vector<uint8_t> &plain_text, uint8_t key)
    {
        std::vector<uint8_t> cipher_text(plain_text.size());
        std::transform(plain_text.cbegin(), plain_text.cend(), cipher_text.begin(),
            [key](uint8_t byte_in) { return byte_in ^ key; });
        return cipher_text;
    }

    TransferHandle create_transfer_handle()
    {
        const std::string file_hash {"Ionut Cercel - Made in Romania - manele vechi"};
        const SearchId    search_id {1};
        const OfferId     offer_id {2};
        const std::string sender_public_key {"parola123"};
        const std::vector<TransferHandleImpl::PartData> parts {
            {conversion::to_ipv4_address("69.69.69.69"), 0, 1024},
            {conversion::to_ipv4_address("69.69.69.70"), 1024, 512}};

        std::vector<uint8_t> key(16), iv(16);
        std::generate(key.begin(), key.end(), [&] { return rng_.next<Byte>(); });
        std::generate(iv.begin(), iv.end(), [&] { return rng_.next<Byte>(); });

        TransferKey transfer_key;
        std::copy(
            iv.cbegin(), iv.cend(), std::copy(key.cbegin(), key.cend(), transfer_key.begin()));

        return TransferHandle {std::make_shared<TransferHandleImpl>(
            SearchHandleImpl {file_hash, search_id, sender_public_key}, offer_id, transfer_key,
            parts)};
    }

    static size_t add_padding(size_t initial_size, size_t block_size = 16)
    {
        if (initial_size % block_size != 0)
        {
            initial_size = (initial_size / block_size + 1) * block_size;
        }
        return initial_size;
    }

    std::shared_ptr<ProtocolMessageHandlerMock>   protocol_message_handler_;
    std::shared_ptr<InboundRequestDispatcher>     inbound_request_dispatcher_;
    std::shared_ptr<PeerAddressProviderMock>      peer_address_provider_;
    std::shared_ptr<FileStorageMock>              file_storage_;
    FileHashInterpreterMock *                     file_hash_interpreter_;
    std::shared_ptr<TemporaryDataStorageMock>     temporary_data_storage_;
    std::shared_ptr<AESCipherMock>                aes_;
    std::shared_ptr<Executer>                     thread_pool_;
    std::shared_ptr<FileTransferFlowListenerMock> listener_;
    Random                                        rng_;
    const size_t                                  max_part_size_         = 1024;  // 1KiB
    const size_t                                  max_chunk_size_        = 128;
    const size_t                                  max_temp_storage_size_ = 4096;  // 4KiB
};
}  // namespace

TEST_F(FileTransferFlowTest, StateChanges)
{
    auto flow = make_flow();
    EXPECT_EQ(flow->state(), FileTransferFlow::State::IDLE);

    flow->start();
    EXPECT_EQ(flow->state(), FileTransferFlow::State::RUNNING);

    flow->stop();
    EXPECT_EQ(flow->state(), FileTransferFlow::State::IDLE);
}

TEST_F(FileTransferFlowTest, StateChangesAreNotified)
{
    auto flow = make_flow();
    flow->register_listener(listener_);

    EXPECT_CALL(*listener_, on_state_changed(FileTransferFlow::State::RUNNING)).Times(1);
    flow->start();
    Mock::VerifyAndClearExpectations(listener_.get());

    EXPECT_CALL(*listener_, on_state_changed(FileTransferFlow::State::STOPPING)).Times(1);
    EXPECT_CALL(*listener_, on_state_changed(FileTransferFlow::State::IDLE)).Times(1);
    flow->stop();
}

TEST_F(FileTransferFlowTest, CreateOffer_OnePart)
{
    const std::string file_hash {"Ionut Cercel - Made in Romania - manele vechi"};
    const SearchId    search_id {1};
    const std::string sender_public_key {"parola123"};
    const size_t      file_size {666};
    const size_t      padded_file_size {672};
    const IPv4Address drop_point {conversion::to_ipv4_address("69.69.69.69")};

    AHash bin_file_hash;
    std::generate(bin_file_hash.begin(), bin_file_hash.end(), [&] { return rng_.next<Byte>(); });

    std::vector<uint8_t> key(16), iv(16);
    std::generate(key.begin(), key.end(), [&] { return rng_.next<Byte>(); });
    std::generate(iv.begin(), iv.end(), [&] { return rng_.next<Byte>(); });

    TransferKey transfer_key;
    std::copy(iv.cbegin(), iv.cend(), std::copy(key.cbegin(), key.cend(), transfer_key.begin()));

    SearchHandle search_handle {
        std::make_shared<SearchHandleImpl>(file_hash, search_id, sender_public_key)};

    ON_CALL(*file_storage_, contains(file_hash)).WillByDefault(Return(true));
    ON_CALL(*file_hash_interpreter_, decode(file_hash, _))
        .WillByDefault(DoAll(SetArgReferee<1>(bin_file_hash), Return(true)));
    ON_CALL(*file_hash_interpreter_, get_file_size(bin_file_hash)).WillByDefault(Return(file_size));
    ON_CALL(*aes_, generate_key_and_iv(AESCipher::AES128, AESCipher::CBC, _, _))
        .WillByDefault(DoAll(SetArgReferee<2>(key), SetArgReferee<3>(iv), Return(true)));

    EXPECT_CALL(*peer_address_provider_, get_peers(1, _))
        .Times(1)
        .WillOnce(make_get_peers_action(std::vector<IPv4Address> {drop_point}));
    EXPECT_CALL(*protocol_message_handler_,
        send(drop_point, ResultOf([](auto &&ptr) { return ptr.get(); },
                             WhenDynamicCastTo<RequestDropPointMessage *>(Pointee(
                                 Field(&RequestDropPointMessage::part_size, padded_file_size))))))
        .Times(1)
        .WillOnce(make_send_message_action(StatusCode::OK));

    auto flow = make_flow();
    flow->start();

    TransferHandle transfer_handle = flow->create_offer(search_handle).get();
    EXPECT_TRUE(transfer_handle.is_valid());

    auto transfer_handle_data = transfer_handle.data();
    auto search_handle_data   = search_handle.data();

    EXPECT_EQ(transfer_handle_data->search_handle.search_id, search_handle_data->search_id);
    EXPECT_EQ(transfer_handle_data->search_handle.file_hash, search_handle_data->file_hash);
    EXPECT_EQ(transfer_handle_data->search_handle.sender_public_key,
        search_handle_data->sender_public_key);
    EXPECT_EQ(transfer_handle_data->transfer_key, transfer_key);
    EXPECT_EQ(transfer_handle_data->parts.size(), 1);

    auto part_data = transfer_handle_data->parts[0];

    EXPECT_EQ(part_data.part_size, file_size);
    EXPECT_EQ(part_data.drop_point, drop_point);
    EXPECT_EQ(part_data.part_offset, 0);
}

TEST_F(FileTransferFlowTest, CreateOffer_MultipleParts)
{
    const std::string              file_hash {"Ionut Cercel - Made in Romania - manele vechi"};
    const SearchId                 search_id {1};
    const std::string              sender_public_key {"parola123"};
    const size_t                   file_size {2999};
    const size_t                   last_part_size {951};
    const size_t                   last_padded_part_size {960};
    const std::vector<IPv4Address> drop_points {conversion::to_ipv4_address("69.69.69.69"),
        conversion::to_ipv4_address("69.69.69.70"), conversion::to_ipv4_address("69.69.69.71")};

    AHash bin_file_hash;
    std::generate(bin_file_hash.begin(), bin_file_hash.end(), [&] { return rng_.next<Byte>(); });

    std::vector<uint8_t> key(16), iv(16);
    std::generate(key.begin(), key.end(), [&] { return rng_.next<Byte>(); });
    std::generate(iv.begin(), iv.end(), [&] { return rng_.next<Byte>(); });

    TransferKey transfer_key;
    std::copy(iv.cbegin(), iv.cend(), std::copy(key.cbegin(), key.cend(), transfer_key.begin()));

    SearchHandle search_handle {
        std::make_shared<SearchHandleImpl>(file_hash, search_id, sender_public_key)};

    ON_CALL(*file_storage_, contains(file_hash)).WillByDefault(Return(true));
    ON_CALL(*file_hash_interpreter_, decode(file_hash, _))
        .WillByDefault(DoAll(SetArgReferee<1>(bin_file_hash), Return(true)));
    ON_CALL(*file_hash_interpreter_, get_file_size(bin_file_hash)).WillByDefault(Return(file_size));
    ON_CALL(*aes_, generate_key_and_iv(AESCipher::AES128, AESCipher::CBC, _, _))
        .WillByDefault(DoAll(SetArgReferee<2>(key), SetArgReferee<3>(iv), Return(true)));

    EXPECT_CALL(*peer_address_provider_, get_peers(3, _))
        .Times(1)
        .WillOnce(make_get_peers_action(drop_points));
    EXPECT_CALL(*protocol_message_handler_,
        send(drop_points[0], ResultOf([](auto &&ptr) { return ptr.get(); },
                                 WhenDynamicCastTo<RequestDropPointMessage *>(Pointee(
                                     Field(&RequestDropPointMessage::part_size, max_part_size_))))))
        .Times(1)
        .WillOnce(make_send_message_action(StatusCode::OK));
    EXPECT_CALL(*protocol_message_handler_,
        send(drop_points[1], ResultOf([](auto &&ptr) { return ptr.get(); },
                                 WhenDynamicCastTo<RequestDropPointMessage *>(Pointee(
                                     Field(&RequestDropPointMessage::part_size, max_part_size_))))))
        .Times(1)
        .WillOnce(make_send_message_action(StatusCode::OK));
    EXPECT_CALL(*protocol_message_handler_,
        send(drop_points[2],
            ResultOf([](auto &&ptr) { return ptr.get(); },
                WhenDynamicCastTo<RequestDropPointMessage *>(
                    Pointee(Field(&RequestDropPointMessage::part_size, last_padded_part_size))))))
        .Times(1)
        .WillOnce(make_send_message_action(StatusCode::OK));

    auto flow = make_flow();
    flow->start();

    TransferHandle transfer_handle = flow->create_offer(search_handle).get();
    EXPECT_TRUE(transfer_handle.is_valid());

    auto transfer_handle_data = transfer_handle.data();
    auto search_handle_data   = search_handle.data();

    EXPECT_EQ(transfer_handle_data->search_handle.search_id, search_handle_data->search_id);
    EXPECT_EQ(transfer_handle_data->search_handle.file_hash, search_handle_data->file_hash);
    EXPECT_EQ(transfer_handle_data->search_handle.sender_public_key,
        search_handle_data->sender_public_key);
    EXPECT_EQ(transfer_handle_data->transfer_key, transfer_key);
    EXPECT_EQ(transfer_handle_data->parts.size(), 3);

    const auto &parts = transfer_handle_data->parts;

    EXPECT_EQ(parts[0].part_size, max_part_size_);
    EXPECT_EQ(parts[0].drop_point, drop_points[0]);
    EXPECT_EQ(parts[0].part_offset, 0);
    EXPECT_EQ(parts[1].part_size, max_part_size_);
    EXPECT_EQ(parts[1].drop_point, drop_points[1]);
    EXPECT_EQ(parts[1].part_offset, max_part_size_);
    EXPECT_EQ(parts[2].part_size, last_part_size);
    EXPECT_EQ(parts[2].drop_point, drop_points[2]);
    EXPECT_EQ(parts[2].part_offset, 2 * max_part_size_);
}

TEST_F(FileTransferFlowTest, CreateOffer_FlowNotStarted)
{
    const std::string file_hash {"Ionut Cercel - Made in Romania - manele vechi"};
    const SearchId    search_id {1};
    const std::string sender_public_key {"parola123"};

    SearchHandle search_handle {
        std::make_shared<SearchHandleImpl>(file_hash, search_id, sender_public_key)};

    auto flow = make_flow();

    TransferHandle transfer_handle = flow->create_offer(search_handle).get();
    EXPECT_FALSE(transfer_handle.is_valid());
}

TEST_F(FileTransferFlowTest, CreateOffer_UnknownFile)
{
    const std::string file_hash {"Ionut Cercel - Made in Romania - manele vechi"};
    const SearchId    search_id {1};
    const std::string sender_public_key {"parola123"};

    SearchHandle search_handle {
        std::make_shared<SearchHandleImpl>(file_hash, search_id, sender_public_key)};

    ON_CALL(*file_storage_, contains(file_hash)).WillByDefault(Return(false));

    auto flow = make_flow();
    flow->start();

    TransferHandle transfer_handle = flow->create_offer(search_handle).get();
    EXPECT_FALSE(transfer_handle.is_valid());
}

TEST_F(FileTransferFlowTest, CreateOffer_FileHashDecodingError)
{
    const std::string file_hash {"Ionut Cercel - Made in Romania - manele vechi"};
    const SearchId    search_id {1};
    const std::string sender_public_key {"parola123"};

    SearchHandle search_handle {
        std::make_shared<SearchHandleImpl>(file_hash, search_id, sender_public_key)};

    ON_CALL(*file_storage_, contains(file_hash)).WillByDefault(Return(true));
    ON_CALL(*file_hash_interpreter_, decode(file_hash, _)).WillByDefault(Return(false));

    auto flow = make_flow();
    flow->start();

    TransferHandle transfer_handle = flow->create_offer(search_handle).get();
    EXPECT_FALSE(transfer_handle.is_valid());
}

TEST_F(FileTransferFlowTest, CreateOffer_NotEnoughPeers)
{
    const std::string file_hash {"Ionut Cercel - Made in Romania - manele vechi"};
    const SearchId    search_id {1};
    const std::string sender_public_key {"parola123"};
    const size_t      file_size {666};

    AHash bin_file_hash;
    std::generate(bin_file_hash.begin(), bin_file_hash.end(), [&] { return rng_.next<Byte>(); });

    SearchHandle search_handle {
        std::make_shared<SearchHandleImpl>(file_hash, search_id, sender_public_key)};

    ON_CALL(*file_storage_, contains(file_hash)).WillByDefault(Return(true));
    ON_CALL(*file_hash_interpreter_, decode(file_hash, _))
        .WillByDefault(DoAll(SetArgReferee<1>(bin_file_hash), Return(true)));
    ON_CALL(*file_hash_interpreter_, get_file_size(bin_file_hash)).WillByDefault(Return(file_size));

    EXPECT_CALL(*peer_address_provider_, get_peers(1, _))
        .Times(1)
        .WillOnce(make_get_peers_action(std::vector<IPv4Address> {}));

    auto flow = make_flow();
    flow->start();

    TransferHandle transfer_handle = flow->create_offer(search_handle).get();
    EXPECT_FALSE(transfer_handle.is_valid());
}

TEST_F(FileTransferFlowTest, CreateOffer_PeerRefusesDropPointRequest)
{
    const std::string file_hash {"Ionut Cercel - Made in Romania - manele vechi"};
    const SearchId    search_id {1};
    const std::string sender_public_key {"parola123"};
    const size_t      file_size {666};
    const size_t      padded_file_size {672};
    const IPv4Address drop_point_bad {conversion::to_ipv4_address("69.69.69.69")};
    const IPv4Address drop_point_good {conversion::to_ipv4_address("69.69.69.70")};

    AHash bin_file_hash;
    std::generate(bin_file_hash.begin(), bin_file_hash.end(), [&] { return rng_.next<Byte>(); });

    std::vector<uint8_t> key(16), iv(16);
    std::generate(key.begin(), key.end(), [&] { return rng_.next<Byte>(); });
    std::generate(iv.begin(), iv.end(), [&] { return rng_.next<Byte>(); });

    TransferKey transfer_key;
    std::copy(iv.cbegin(), iv.cend(), std::copy(key.cbegin(), key.cend(), transfer_key.begin()));

    SearchHandle search_handle {
        std::make_shared<SearchHandleImpl>(file_hash, search_id, sender_public_key)};

    ON_CALL(*file_storage_, contains(file_hash)).WillByDefault(Return(true));
    ON_CALL(*file_hash_interpreter_, decode(file_hash, _))
        .WillByDefault(DoAll(SetArgReferee<1>(bin_file_hash), Return(true)));
    ON_CALL(*file_hash_interpreter_, get_file_size(bin_file_hash)).WillByDefault(Return(file_size));
    ON_CALL(*aes_, generate_key_and_iv(AESCipher::AES128, AESCipher::CBC, _, _))
        .WillByDefault(DoAll(SetArgReferee<2>(key), SetArgReferee<3>(iv), Return(true)));

    EXPECT_CALL(*peer_address_provider_, get_peers(1, _))
        .Times(2)
        .WillOnce(make_get_peers_action(std::vector<IPv4Address> {drop_point_bad}))
        .WillOnce(make_get_peers_action(std::vector<IPv4Address> {drop_point_good}));
    EXPECT_CALL(*protocol_message_handler_,
        send(drop_point_bad, ResultOf([](auto &&ptr) { return ptr.get(); },
                                 WhenDynamicCastTo<RequestDropPointMessage *>(Pointee(Field(
                                     &RequestDropPointMessage::part_size, padded_file_size))))))
        .Times(1)
        .WillOnce(make_send_message_action(StatusCode::DENY));
    EXPECT_CALL(*protocol_message_handler_,
        send(drop_point_good, ResultOf([](auto &&ptr) { return ptr.get(); },
                                  WhenDynamicCastTo<RequestDropPointMessage *>(Pointee(Field(
                                      &RequestDropPointMessage::part_size, padded_file_size))))))
        .Times(1)
        .WillOnce(make_send_message_action(StatusCode::OK));

    auto flow = make_flow();
    flow->start();

    TransferHandle transfer_handle = flow->create_offer(search_handle).get();
    EXPECT_TRUE(transfer_handle.is_valid());

    auto transfer_handle_data = transfer_handle.data();
    auto search_handle_data   = search_handle.data();

    EXPECT_EQ(transfer_handle_data->search_handle.search_id, search_handle_data->search_id);
    EXPECT_EQ(transfer_handle_data->search_handle.file_hash, search_handle_data->file_hash);
    EXPECT_EQ(transfer_handle_data->search_handle.sender_public_key,
        search_handle_data->sender_public_key);
    EXPECT_EQ(transfer_handle_data->transfer_key, transfer_key);
    EXPECT_EQ(transfer_handle_data->parts.size(), 1);

    auto part_data = transfer_handle_data->parts[0];

    EXPECT_EQ(part_data.part_size, file_size);
    EXPECT_EQ(part_data.drop_point, drop_point_good);
    EXPECT_EQ(part_data.part_offset, 0);
}

TEST_F(FileTransferFlowTest, SendFile)
{
    TransferHandle transfer_handle      = create_transfer_handle();
    auto           transfer_handle_data = transfer_handle.data();
    const size_t   file_size =
        transfer_handle_data->parts[0].part_size + transfer_handle_data->parts[1].part_size;
    const int     chunks_count = int(file_size / max_chunk_size_ + (file_size % max_chunk_size_));
    const uint8_t xor_encryption_key = 0x69;

    AHash bin_file_hash;
    std::generate(bin_file_hash.begin(), bin_file_hash.end(), [&] { return rng_.next<Byte>(); });

    std::vector<uint8_t> file_content(file_size);
    std::generate(file_content.begin(), file_content.end(), [&] { return rng_.next<uint8_t>(); });

    ON_CALL(*file_hash_interpreter_, decode(transfer_handle_data->search_handle.file_hash, _))
        .WillByDefault(DoAll(SetArgReferee<1>(bin_file_hash), Return(true)));
    ON_CALL(*file_hash_interpreter_, get_file_size(bin_file_hash)).WillByDefault(Return(file_size));
    ON_CALL(*file_storage_, read_file(transfer_handle_data->search_handle.file_hash, _, _, _))
        .WillByDefault([&](const std::string &, size_t offset, size_t amount, uint8_t *out) {
            std::copy_n(&file_content[offset], amount, out);
            return true;
        });
    ON_CALL(*file_storage_, close_file(transfer_handle_data->search_handle.file_hash))
        .WillByDefault(Return(true));
    ON_CALL(*aes_, encrypt(AESCipher::CBC, _, _, _, _))
        .WillByDefault([&](AESCipher::ModeOfOperation, const AESCipher::ByteVector &,
                           const AESCipher::ByteVector &, const AESCipher::ByteVector &plain_text,
                           Executer &) {
            std::promise<AESCipher::ByteVector> promise;
            promise.set_value(xor_encrypt(plain_text, xor_encryption_key));
            return promise.get_future();
        });

    for (const auto &part_data : transfer_handle_data->parts)
    {
        EXPECT_CALL(*protocol_message_handler_,
            send(part_data.drop_point,
                ResultOf([](auto &&ptr) { return ptr.get(); },
                    WhenDynamicCastTo<InitUploadMessage *>(Pointee(
                        Field(&InitUploadMessage::offer_id, transfer_handle_data->offer_id))))))
            .Times(1)
            .WillOnce(make_send_message_action(StatusCode::OK));
    }

    for (const auto &part_data : transfer_handle_data->parts)
    {
        for (size_t offset = 0; offset < part_data.part_size; offset += max_chunk_size_)
        {
            // PRAJEALA
            EXPECT_CALL(*protocol_message_handler_,
                send(part_data.drop_point,
                    ResultOf([](auto &&ptr) { return ptr.get(); },
                        WhenDynamicCastTo<UploadMessage *>(Pointee(AllOf(
                            Field(&UploadMessage::offer_id, transfer_handle_data->offer_id),
                            Field(&UploadMessage::offset, offset),
                            Field(&UploadMessage::data, Truly([=](auto &&data) {
                                auto plain_text_data = xor_encrypt(data, xor_encryption_key);
                                return data.size() == std::min(max_chunk_size_,
                                                          part_data.part_size - offset) &&
                                       std::equal(plain_text_data.cbegin(), plain_text_data.cend(),
                                           &file_content[part_data.part_offset + offset]);
                            }))))))))
                .Times(1)
                .WillOnce(make_send_message_action(StatusCode::OK));
        }
    }

    EXPECT_CALL(*listener_,
        on_transfer_progress_changed(
            ResultOf([](auto &&th) { return th.data(); }, transfer_handle_data), _, file_size))
        .Times(chunks_count);
    EXPECT_CALL(*listener_,
        on_transfer_completed(ResultOf([](auto &&th) { return th.data(); }, transfer_handle_data)))
        .Times(1);

    auto flow = make_flow();
    flow->start();
    flow->register_listener(listener_);

    EXPECT_TRUE(flow->send_file(transfer_handle));
    thread_pool_->process_all_jobs();
}

TEST_F(FileTransferFlowTest, SendFile_FlowNotStarted)
{
    TransferHandle transfer_handle = create_transfer_handle();
    auto           flow            = make_flow();
    EXPECT_FALSE(flow->send_file(transfer_handle));
}

TEST_F(FileTransferFlowTest, SendFile_InvalidTransferHandle)
{
    TransferHandle transfer_handle;
    auto           flow = make_flow();
    flow->start();
    EXPECT_FALSE(flow->send_file(transfer_handle));
}

TEST_F(FileTransferFlowTest, SendFile_PeerDeniesInitUpload)
{
    TransferHandle transfer_handle      = create_transfer_handle();
    auto           transfer_handle_data = transfer_handle.data();
    const size_t   file_size =
        transfer_handle_data->parts[0].part_size + transfer_handle_data->parts[1].part_size;

    AHash bin_file_hash;
    std::generate(bin_file_hash.begin(), bin_file_hash.end(), [&] { return rng_.next<Byte>(); });

    ON_CALL(*file_hash_interpreter_, decode(transfer_handle_data->search_handle.file_hash, _))
        .WillByDefault(DoAll(SetArgReferee<1>(bin_file_hash), Return(true)));
    ON_CALL(*file_hash_interpreter_, get_file_size(bin_file_hash)).WillByDefault(Return(file_size));

    EXPECT_CALL(*protocol_message_handler_,
        send(AnyOf(transfer_handle_data->parts[0].drop_point,
                 transfer_handle_data->parts[1].drop_point),
            ResultOf([](auto &&ptr) { return ptr.get(); },
                WhenDynamicCastTo<InitUploadMessage *>(
                    Pointee(Field(&InitUploadMessage::offer_id, transfer_handle_data->offer_id))))))
        .Times(2)
        .WillOnce(make_send_message_action(StatusCode::OK))
        .WillOnce(make_send_message_action(StatusCode::DENY));

    EXPECT_CALL(*listener_,
        on_transfer_error(ResultOf([](auto &&th) { return th.data(); }, transfer_handle_data), _))
        .Times(1);
    EXPECT_CALL(*listener_, on_transfer_completed(_)).Times(0);

    auto flow = make_flow();
    flow->start();
    flow->register_listener(listener_);

    EXPECT_TRUE(flow->send_file(transfer_handle));
    thread_pool_->process_all_jobs();
}

TEST_F(FileTransferFlowTest, SendFile_PeerDeniesUpload)
{
    TransferHandle transfer_handle      = create_transfer_handle();
    auto           transfer_handle_data = transfer_handle.data();
    const size_t   file_size =
        transfer_handle_data->parts[0].part_size + transfer_handle_data->parts[1].part_size;
    const uint8_t xor_encryption_key = 0x69;

    AHash bin_file_hash;
    std::generate(bin_file_hash.begin(), bin_file_hash.end(), [&] { return rng_.next<Byte>(); });

    std::vector<uint8_t> file_content(file_size);
    std::generate(file_content.begin(), file_content.end(), [&] { return rng_.next<uint8_t>(); });

    ON_CALL(*file_hash_interpreter_, decode(transfer_handle_data->search_handle.file_hash, _))
        .WillByDefault(DoAll(SetArgReferee<1>(bin_file_hash), Return(true)));
    ON_CALL(*file_hash_interpreter_, get_file_size(bin_file_hash)).WillByDefault(Return(file_size));
    ON_CALL(*file_storage_, read_file(transfer_handle_data->search_handle.file_hash, _, _, _))
        .WillByDefault([&](const std::string &, size_t offset, size_t amount, uint8_t *out) {
            std::copy_n(&file_content[offset], amount, out);
            return true;
        });
    ON_CALL(*file_storage_, close_file(transfer_handle_data->search_handle.file_hash))
        .WillByDefault(Return(true));
    ON_CALL(*aes_, encrypt(AESCipher::CBC, _, _, _, _))
        .WillByDefault([&](AESCipher::ModeOfOperation, const AESCipher::ByteVector &,
                           const AESCipher::ByteVector &, const AESCipher::ByteVector &plain_text,
                           Executer &) {
            std::promise<AESCipher::ByteVector> promise;
            promise.set_value(xor_encrypt(plain_text, xor_encryption_key));
            return promise.get_future();
        });

    for (const auto &part_data : transfer_handle_data->parts)
    {
        EXPECT_CALL(*protocol_message_handler_,
            send(part_data.drop_point,
                ResultOf([](auto &&ptr) { return ptr.get(); },
                    WhenDynamicCastTo<InitUploadMessage *>(Pointee(
                        Field(&InitUploadMessage::offer_id, transfer_handle_data->offer_id))))))
            .Times(1)
            .WillOnce(make_send_message_action(StatusCode::OK));
    }

    EXPECT_CALL(*protocol_message_handler_,
        send(transfer_handle_data->parts[0].drop_point,
            Truly([](auto &&ptr) { return bool(dynamic_cast<UploadMessage *>(ptr.get())); })))
        .Times(AnyNumber())
        .WillRepeatedly(make_send_message_action(StatusCode::OK));
    EXPECT_CALL(*protocol_message_handler_,
        send(transfer_handle_data->parts[1].drop_point,
            Truly([](auto &&ptr) { return bool(dynamic_cast<UploadMessage *>(ptr.get())); })))
        .Times(1)
        .WillOnce(make_send_message_action(StatusCode::DENY));

    EXPECT_CALL(*listener_,
        on_transfer_error(ResultOf([](auto &&th) { return th.data(); }, transfer_handle_data), _))
        .Times(1);
    EXPECT_CALL(*listener_, on_transfer_completed(_)).Times(0);

    auto flow = make_flow();
    flow->start();
    flow->register_listener(listener_);

    EXPECT_TRUE(flow->send_file(transfer_handle));
    thread_pool_->process_all_jobs();
}

TEST_F(FileTransferFlowTest, ReceiveFile)
{
    TransferHandle transfer_handle      = create_transfer_handle();
    auto           transfer_handle_data = transfer_handle.data();
    const size_t   file_size =
        transfer_handle_data->parts[0].part_size + transfer_handle_data->parts[1].part_size;
    const std::vector<IPv4Address> lift_proxies {
        conversion::to_ipv4_address("1.1.1.1"), conversion::to_ipv4_address("1.1.1.2")};
    const uint8_t xor_encryption_key = 0x69;
    const int     chunks_count = int(file_size / max_chunk_size_ + (file_size % max_chunk_size_));

    AHash bin_file_hash;
    std::generate(bin_file_hash.begin(), bin_file_hash.end(), [&] { return rng_.next<Byte>(); });

    std::vector<uint8_t> file_content(file_size), received_file_content(file_size);
    std::generate(file_content.begin(), file_content.end(), [&] { return rng_.next<uint8_t>(); });

    ON_CALL(*file_hash_interpreter_, decode(transfer_handle_data->search_handle.file_hash, _))
        .WillByDefault(DoAll(SetArgReferee<1>(bin_file_hash), Return(true)));
    ON_CALL(*file_hash_interpreter_, get_file_size(bin_file_hash)).WillByDefault(Return(file_size));
    ON_CALL(*aes_, decrypt(AESCipher::CBC, _, _, _, _))
        .WillByDefault([&](AESCipher::ModeOfOperation, const AESCipher::ByteVector &,
                           const AESCipher::ByteVector &, const AESCipher::ByteVector &cipher_text,
                           Executer &) {
            std::promise<AESCipher::ByteVector> promise;
            promise.set_value(xor_encrypt(cipher_text, xor_encryption_key));
            return promise.get_future();
        });
    ON_CALL(*file_storage_, write_file(transfer_handle_data->search_handle.file_hash, _, _, _))
        .WillByDefault([&](const std::string & /*file_hash*/, size_t offset, size_t amount,
                           const uint8_t *in) {
            auto it = received_file_content.begin();
            std::advance(it, offset);
            std::copy_n(in, amount, it);
            return true;
        });
    ON_CALL(*file_storage_, close_file(transfer_handle_data->search_handle.file_hash))
        .WillByDefault(Return(true));

    EXPECT_CALL(*peer_address_provider_, get_peers(2, _))
        .Times(1)
        .WillOnce(make_get_peers_action(lift_proxies));

    for (size_t i = 0; i != lift_proxies.size(); ++i)
    {
        const auto &part_data       = transfer_handle_data->parts[i];
        IPv4Address lift_proxy_addr = lift_proxies[i];

        EXPECT_CALL(*protocol_message_handler_,
            send(lift_proxy_addr,
                ResultOf([](auto &&ptr) { return ptr.get(); },
                    WhenDynamicCastTo<RequestLiftProxyMessage *>(Pointee(Field(
                        &RequestLiftProxyMessage::part_size, add_padding(part_data.part_size)))))))
            .Times(1)
            .WillOnce(make_send_message_action(StatusCode::OK));
        EXPECT_CALL(*protocol_message_handler_,
            send(lift_proxy_addr,
                ResultOf([](auto &&ptr) { return ptr.get(); },
                    WhenDynamicCastTo<FetchMessage *>(Pointee(
                        AllOf(Field(&FetchMessage::offer_id, transfer_handle_data->offer_id),
                            Field(&FetchMessage::drop_point, part_data.drop_point)))))))
            .Times(1)
            .WillOnce(make_send_message_action(StatusCode::OK));
    }

    EXPECT_CALL(*listener_,
        on_transfer_progress_changed(
            ResultOf([](auto &&th) { return th.data(); }, transfer_handle_data), _, file_size))
        .Times(chunks_count);
    EXPECT_CALL(*listener_,
        on_transfer_completed(ResultOf([](auto &&th) { return th.data(); }, transfer_handle_data)))
        .Times(1);

    auto flow = make_flow();
    flow->start();
    flow->register_listener(listener_);

    EXPECT_TRUE(flow->receive_file(transfer_handle));
    thread_pool_->process_all_jobs();

    for (size_t i = 0; i != lift_proxies.size(); ++i)
    {
        const auto &part_data       = transfer_handle_data->parts[i];
        IPv4Address lift_proxy_addr = lift_proxies[i];

        for (PartSize offset = 0; offset < part_data.part_size; offset += PartSize(max_chunk_size_))
        {
            auto   request_id = rng_.next<RequestId>();
            size_t chunk_size = std::min(max_chunk_size_, size_t(part_data.part_size - offset));

            UploadMessage msg;
            msg.request_id = request_id;
            msg.offset     = offset;
            msg.offer_id   = transfer_handle_data->offer_id;

            std::vector<uint8_t> chunk_data(chunk_size);
            auto                 it = file_content.cbegin();
            std::advance(it, part_data.part_offset + offset);
            std::copy_n(it, chunk_size, chunk_data.begin());
            msg.data = xor_encrypt(chunk_data, xor_encryption_key);

            EXPECT_CALL(*protocol_message_handler_,
                send_reply(lift_proxy_addr,
                    ResultOf([](auto &&ptr) { return ptr.get(); },
                        Pointee(AllOf(Field(&BasicReply::request_message_code, MessageCode::UPLOAD),
                            Field(&BasicReply::status_code, StatusCode::OK),
                            Field(&BasicReply::request_id, request_id))))))
                .Times(1)
                .WillOnce(make_send_reply_action());

            inbound_request_dispatcher_->on_message_received(lift_proxy_addr, msg);
        }
    }

    thread_pool_->process_all_jobs();

    ASSERT_THAT(file_content, ContainerEq(received_file_content));
}

TEST_F(FileTransferFlowTest, ReceiveFile_FlowNotStarted)
{
    TransferHandle transfer_handle = create_transfer_handle();
    auto           flow            = make_flow();
    EXPECT_FALSE(flow->receive_file(transfer_handle));
}

TEST_F(FileTransferFlowTest, ReceiveFile_InvalidTransferHandle)
{
    TransferHandle transfer_handle;
    auto           flow = make_flow();
    flow->start();
    EXPECT_FALSE(flow->receive_file(transfer_handle));
}

TEST_F(FileTransferFlowTest, ReceiveFile_NotEnoughLiftProxiesAvailable)
{
    TransferHandle transfer_handle      = create_transfer_handle();
    auto           transfer_handle_data = transfer_handle.data();
    const size_t   file_size =
        transfer_handle_data->parts[0].part_size + transfer_handle_data->parts[1].part_size;
    const std::vector<IPv4Address> lift_proxies {conversion::to_ipv4_address("1.1.1.1")};

    AHash bin_file_hash;
    std::generate(bin_file_hash.begin(), bin_file_hash.end(), [&] { return rng_.next<Byte>(); });

    ON_CALL(*file_hash_interpreter_, decode(transfer_handle_data->search_handle.file_hash, _))
        .WillByDefault(DoAll(SetArgReferee<1>(bin_file_hash), Return(true)));
    ON_CALL(*file_hash_interpreter_, get_file_size(bin_file_hash)).WillByDefault(Return(file_size));

    EXPECT_CALL(*peer_address_provider_, get_peers(2, _))
        .Times(1)
        .WillOnce(make_get_peers_action(lift_proxies));

    EXPECT_CALL(*listener_,
        on_transfer_completed(ResultOf([](auto &&th) { return th.data(); }, transfer_handle_data)))
        .Times(0);
    EXPECT_CALL(*listener_,
        on_transfer_error(ResultOf([](auto &&th) { return th.data(); }, transfer_handle_data), _))
        .Times(1);

    auto flow = make_flow();
    flow->start();
    flow->register_listener(listener_);

    EXPECT_TRUE(flow->receive_file(transfer_handle));
    thread_pool_->process_all_jobs();
}

TEST_F(FileTransferFlowTest, ReceiveFile_PeerDeniesFetch)
{
    TransferHandle transfer_handle      = create_transfer_handle();
    auto           transfer_handle_data = transfer_handle.data();
    const size_t   file_size =
        transfer_handle_data->parts[0].part_size + transfer_handle_data->parts[1].part_size;
    const std::vector<IPv4Address> lift_proxies {
        conversion::to_ipv4_address("1.1.1.1"), conversion::to_ipv4_address("1.1.1.2")};

    AHash bin_file_hash;
    std::generate(bin_file_hash.begin(), bin_file_hash.end(), [&] { return rng_.next<Byte>(); });

    ON_CALL(*file_hash_interpreter_, decode(transfer_handle_data->search_handle.file_hash, _))
        .WillByDefault(DoAll(SetArgReferee<1>(bin_file_hash), Return(true)));
    ON_CALL(*file_hash_interpreter_, get_file_size(bin_file_hash)).WillByDefault(Return(file_size));

    EXPECT_CALL(*peer_address_provider_, get_peers(2, _))
        .Times(1)
        .WillOnce(make_get_peers_action(lift_proxies));

    for (size_t i = 0; i != lift_proxies.size(); ++i)
    {
        const auto &part_data       = transfer_handle_data->parts[i];
        IPv4Address lift_proxy_addr = lift_proxies[i];

        EXPECT_CALL(*protocol_message_handler_,
            send(lift_proxy_addr,
                ResultOf([](auto &&ptr) { return ptr.get(); },
                    WhenDynamicCastTo<RequestLiftProxyMessage *>(Pointee(Field(
                        &RequestLiftProxyMessage::part_size, add_padding(part_data.part_size)))))))
            .Times(1)
            .WillOnce(make_send_message_action(StatusCode::OK));
    }

    EXPECT_CALL(*protocol_message_handler_,
        send(AnyOfArray(lift_proxies),
            ResultOf([](auto &&ptr) { return ptr.get(); },
                WhenDynamicCastTo<FetchMessage *>(
                    Pointee(Field(&FetchMessage::offer_id, transfer_handle_data->offer_id))))))
        .Times(1)
        .WillOnce(make_send_message_action(StatusCode::DENY));

    EXPECT_CALL(*listener_,
        on_transfer_completed(ResultOf([](auto &&th) { return th.data(); }, transfer_handle_data)))
        .Times(0);
    EXPECT_CALL(*listener_,
        on_transfer_error(ResultOf([](auto &&th) { return th.data(); }, transfer_handle_data), _))
        .Times(1);

    auto flow = make_flow();
    flow->start();
    flow->register_listener(listener_);

    EXPECT_TRUE(flow->receive_file(transfer_handle));
    thread_pool_->process_all_jobs();
}

TEST_F(FileTransferFlowTest, ReceiveFile_PeerDeniesRequestLiftProxy)
{
    TransferHandle transfer_handle      = create_transfer_handle();
    auto           transfer_handle_data = transfer_handle.data();
    const size_t   file_size =
        transfer_handle_data->parts[0].part_size + transfer_handle_data->parts[1].part_size;
    const std::vector<IPv4Address> initial_lift_proxies {
        conversion::to_ipv4_address("1.1.1.1"), conversion::to_ipv4_address("1.1.1.2")};
    const IPv4Address              bad_lift_proxy {conversion::to_ipv4_address("1.1.1.2")};
    const IPv4Address              replacement_lift_proxy {conversion::to_ipv4_address("1.1.1.3")};
    const std::vector<IPv4Address> lift_proxies {
        conversion::to_ipv4_address("1.1.1.1"), conversion::to_ipv4_address("1.1.1.3")};
    const uint8_t xor_encryption_key = 0x69;
    const int     chunks_count = int(file_size / max_chunk_size_ + (file_size % max_chunk_size_));

    AHash bin_file_hash;
    std::generate(bin_file_hash.begin(), bin_file_hash.end(), [&] { return rng_.next<Byte>(); });

    std::vector<uint8_t> file_content(file_size), received_file_content(file_size);
    std::generate(file_content.begin(), file_content.end(), [&] { return rng_.next<uint8_t>(); });

    ON_CALL(*file_hash_interpreter_, decode(transfer_handle_data->search_handle.file_hash, _))
        .WillByDefault(DoAll(SetArgReferee<1>(bin_file_hash), Return(true)));
    ON_CALL(*file_hash_interpreter_, get_file_size(bin_file_hash)).WillByDefault(Return(file_size));
    ON_CALL(*aes_, decrypt(AESCipher::CBC, _, _, _, _))
        .WillByDefault([&](AESCipher::ModeOfOperation, const AESCipher::ByteVector &,
                           const AESCipher::ByteVector &, const AESCipher::ByteVector &cipher_text,
                           Executer &) {
            std::promise<AESCipher::ByteVector> promise;
            promise.set_value(xor_encrypt(cipher_text, xor_encryption_key));
            return promise.get_future();
        });
    ON_CALL(*file_storage_, write_file(transfer_handle_data->search_handle.file_hash, _, _, _))
        .WillByDefault([&](const std::string & /*file_hash*/, size_t offset, size_t amount,
                           const uint8_t *in) {
            auto it = received_file_content.begin();
            std::advance(it, offset);
            std::copy_n(in, amount, it);
            return true;
        });
    ON_CALL(*file_storage_, close_file(transfer_handle_data->search_handle.file_hash))
        .WillByDefault(Return(true));

    EXPECT_CALL(*peer_address_provider_, get_peers(2, _))
        .Times(1)
        .WillOnce(make_get_peers_action(initial_lift_proxies));
    EXPECT_CALL(*peer_address_provider_, get_peers(1, _))
        .Times(1)
        .WillOnce(make_get_peers_action(std::vector<IPv4Address> {replacement_lift_proxy}));

    EXPECT_CALL(*protocol_message_handler_, send(bad_lift_proxy, Truly([](auto &&ptr) {
        return bool(dynamic_cast<RequestLiftProxyMessage *>(ptr.get()));
    })))
        .Times(1)
        .WillOnce(make_send_message_action(StatusCode::DENY));
    for (size_t i = 0; i != lift_proxies.size(); ++i)
    {
        const auto &part_data       = transfer_handle_data->parts[i];
        IPv4Address lift_proxy_addr = lift_proxies[i];

        EXPECT_CALL(*protocol_message_handler_,
            send(lift_proxy_addr,
                ResultOf([](auto &&ptr) { return ptr.get(); },
                    WhenDynamicCastTo<RequestLiftProxyMessage *>(Pointee(Field(
                        &RequestLiftProxyMessage::part_size, add_padding(part_data.part_size)))))))
            .Times(1)
            .WillOnce(make_send_message_action(StatusCode::OK));
        EXPECT_CALL(*protocol_message_handler_,
            send(lift_proxy_addr,
                ResultOf([](auto &&ptr) { return ptr.get(); },
                    WhenDynamicCastTo<FetchMessage *>(Pointee(
                        AllOf(Field(&FetchMessage::offer_id, transfer_handle_data->offer_id),
                            Field(&FetchMessage::drop_point, part_data.drop_point)))))))
            .Times(1)
            .WillOnce(make_send_message_action(StatusCode::OK));
    }

    EXPECT_CALL(*listener_,
        on_transfer_progress_changed(
            ResultOf([](auto &&th) { return th.data(); }, transfer_handle_data), _, file_size))
        .Times(chunks_count);
    EXPECT_CALL(*listener_,
        on_transfer_completed(ResultOf([](auto &&th) { return th.data(); }, transfer_handle_data)))
        .Times(1);

    auto flow = make_flow();
    flow->start();
    flow->register_listener(listener_);

    EXPECT_TRUE(flow->receive_file(transfer_handle));
    thread_pool_->process_all_jobs();

    for (size_t i = 0; i != lift_proxies.size(); ++i)
    {
        const auto &part_data       = transfer_handle_data->parts[i];
        IPv4Address lift_proxy_addr = lift_proxies[i];

        for (PartSize offset = 0; offset < part_data.part_size; offset += PartSize(max_chunk_size_))
        {
            auto   request_id = rng_.next<RequestId>();
            size_t chunk_size = std::min(max_chunk_size_, size_t(part_data.part_size - offset));

            UploadMessage msg;
            msg.request_id = request_id;
            msg.offset     = offset;
            msg.offer_id   = transfer_handle_data->offer_id;

            std::vector<uint8_t> chunk_data(chunk_size);
            auto                 it = file_content.cbegin();
            std::advance(it, part_data.part_offset + offset);
            std::copy_n(it, chunk_size, chunk_data.begin());
            msg.data = xor_encrypt(chunk_data, xor_encryption_key);

            EXPECT_CALL(*protocol_message_handler_,
                send_reply(lift_proxy_addr,
                    ResultOf([](auto &&ptr) { return ptr.get(); },
                        Pointee(AllOf(Field(&BasicReply::request_message_code, MessageCode::UPLOAD),
                            Field(&BasicReply::status_code, StatusCode::OK),
                            Field(&BasicReply::request_id, request_id))))))
                .Times(1)
                .WillOnce(make_send_reply_action());

            inbound_request_dispatcher_->on_message_received(lift_proxy_addr, msg);
        }
    }

    thread_pool_->process_all_jobs();

    ASSERT_THAT(file_content, ContainerEq(received_file_content));
}

TEST_F(FileTransferFlowTest, DropPoint_InitUpload_InitDownload_Upload)
{
    const int         number_of_chunks = 3;
    const auto        part_size        = PartSize(max_chunk_size_ * size_t(number_of_chunks));
    const IPv4Address sender_addr {conversion::to_ipv4_address("69.69.69.69")};
    const IPv4Address lift_proxy_addr {conversion::to_ipv4_address("69.69.69.70")};
    const TemporaryDataStorage::Handle temp_storage_handle = 666;
    const auto read_handle = reinterpret_cast<TemporaryDataStorage::ReadHandle *>(420);

    std::vector<uint8_t> file_content(part_size), received_file_content(part_size);
    std::generate(file_content.begin(), file_content.end(), [&] { return rng_.next<uint8_t>(); });

    ON_CALL(*temporary_data_storage_, create(part_size)).WillByDefault(Return(temp_storage_handle));
    ON_CALL(*temporary_data_storage_, start_reading(temp_storage_handle))
        .WillByDefault(Return(read_handle));
    ON_CALL(*temporary_data_storage_, read_next_chunk(read_handle, _, _, _, _))
        .WillByDefault(Return(false));
    ON_CALL(*temporary_data_storage_, cancel_reading(read_handle)).WillByDefault(Return(true));

    auto flow = make_flow();
    flow->start();

    RequestId next_request_id = 1;

    RequestDropPointMessage request_drop_point_msg;
    request_drop_point_msg.request_id = next_request_id++;
    request_drop_point_msg.part_size  = part_size;
    EXPECT_CALL(*protocol_message_handler_,
        send_reply(sender_addr,
            ResultOf([](auto &&ptr) { return ptr.get(); },
                Pointee(
                    AllOf(Field(&BasicReply::request_message_code, MessageCode::REQUESTDROPPOINT),
                        Field(&BasicReply::status_code, StatusCode::OK),
                        Field(&BasicReply::request_id, request_drop_point_msg.request_id))))))
        .Times(1)
        .WillOnce(make_send_reply_action());
    inbound_request_dispatcher_->on_message_received(sender_addr, request_drop_point_msg);

    thread_pool_->process_all_jobs();

    InitUploadMessage init_upload_msg;
    init_upload_msg.request_id = next_request_id++;
    init_upload_msg.offer_id   = 10;
    EXPECT_CALL(*protocol_message_handler_,
        send_reply(sender_addr,
            ResultOf([](auto &&ptr) { return ptr.get(); },
                Pointee(AllOf(Field(&BasicReply::request_message_code, MessageCode::INITUPLOAD),
                    Field(&BasicReply::status_code, StatusCode::OK),
                    Field(&BasicReply::request_id, init_upload_msg.request_id))))))
        .Times(1)
        .WillOnce(make_send_reply_action());
    inbound_request_dispatcher_->on_message_received(sender_addr, init_upload_msg);

    thread_pool_->process_all_jobs();

    InitDownloadMessage init_download_msg;
    init_download_msg.request_id = next_request_id++;
    init_download_msg.offer_id   = 10;
    EXPECT_CALL(*protocol_message_handler_,
        send_reply(lift_proxy_addr,
            ResultOf([](auto &&ptr) { return ptr.get(); },
                Pointee(AllOf(Field(&BasicReply::request_message_code, MessageCode::INITDOWNLOAD),
                    Field(&BasicReply::status_code, StatusCode::OK),
                    Field(&BasicReply::request_id, init_download_msg.request_id))))))
        .Times(1)
        .WillOnce(make_send_reply_action());
    inbound_request_dispatcher_->on_message_received(lift_proxy_addr, init_download_msg);

    thread_pool_->process_all_jobs();

    for (auto it = file_content.cbegin(); it != file_content.cend();
         std::advance(it, max_chunk_size_))
    {
        UploadMessage upload_msg;
        upload_msg.request_id = next_request_id++;
        upload_msg.offer_id   = 10;
        upload_msg.offset     = PartSize(std::distance(file_content.cbegin(), it));
        upload_msg.data.resize(max_chunk_size_);
        std::copy_n(it, max_chunk_size_, upload_msg.data.begin());
        EXPECT_CALL(*protocol_message_handler_,
            send_reply(sender_addr,
                ResultOf([](auto &&ptr) { return ptr.get(); },
                    Pointee(AllOf(Field(&BasicReply::request_message_code, MessageCode::UPLOAD),
                        Field(&BasicReply::status_code, StatusCode::OK),
                        Field(&BasicReply::request_id, upload_msg.request_id))))))
            .Times(1)
            .WillOnce(make_send_reply_action());
        EXPECT_CALL(*protocol_message_handler_,
            send(lift_proxy_addr,
                ResultOf([](auto &&ptr) { return ptr.get(); },
                    WhenDynamicCastTo<UploadMessage *>(
                        Pointee(AllOf(Field(&UploadMessage::offer_id, upload_msg.offer_id),
                            Field(&UploadMessage::offset, upload_msg.offset),
                            Field(&UploadMessage::data, ContainerEq(upload_msg.data))))))))
            .Times(1)
            .WillOnce(make_send_message_action(StatusCode::OK));
        inbound_request_dispatcher_->on_message_received(sender_addr, upload_msg);
    }

    thread_pool_->process_all_jobs();
}

TEST_F(FileTransferFlowTest, DropPoint_InitUpload_Upload_InitDownload)
{
    const int         number_of_chunks = 3;
    const auto        part_size        = PartSize(max_chunk_size_ * size_t(number_of_chunks));
    const IPv4Address sender_addr {conversion::to_ipv4_address("69.69.69.69")};
    const IPv4Address lift_proxy_addr {conversion::to_ipv4_address("69.69.69.70")};
    const TemporaryDataStorage::Handle temp_storage_handle = 666;
    const auto read_handle = reinterpret_cast<TemporaryDataStorage::ReadHandle *>(420);

    std::vector<uint8_t> file_content(part_size), received_file_content(part_size);
    std::generate(file_content.begin(), file_content.end(), [&] { return rng_.next<uint8_t>(); });

    ON_CALL(*temporary_data_storage_, create(part_size)).WillByDefault(Return(temp_storage_handle));
    ON_CALL(*temporary_data_storage_, start_reading(temp_storage_handle))
        .WillByDefault(Return(read_handle));
    ON_CALL(*temporary_data_storage_, cancel_reading(read_handle)).WillByDefault(Return(true));

    auto flow = make_flow();
    flow->start();

    RequestId next_request_id = 1;

    RequestDropPointMessage request_drop_point_msg;
    request_drop_point_msg.request_id = next_request_id++;
    request_drop_point_msg.part_size  = part_size;
    EXPECT_CALL(*protocol_message_handler_,
        send_reply(sender_addr,
            ResultOf([](auto &&ptr) { return ptr.get(); },
                Pointee(
                    AllOf(Field(&BasicReply::request_message_code, MessageCode::REQUESTDROPPOINT),
                        Field(&BasicReply::status_code, StatusCode::OK),
                        Field(&BasicReply::request_id, request_drop_point_msg.request_id))))))
        .Times(1)
        .WillOnce(make_send_reply_action());
    inbound_request_dispatcher_->on_message_received(sender_addr, request_drop_point_msg);

    thread_pool_->process_all_jobs();

    InitUploadMessage init_upload_msg;
    init_upload_msg.request_id = next_request_id++;
    init_upload_msg.offer_id   = 10;
    EXPECT_CALL(*protocol_message_handler_,
        send_reply(sender_addr,
            ResultOf([](auto &&ptr) { return ptr.get(); },
                Pointee(AllOf(Field(&BasicReply::request_message_code, MessageCode::INITUPLOAD),
                    Field(&BasicReply::status_code, StatusCode::OK),
                    Field(&BasicReply::request_id, init_upload_msg.request_id))))))
        .Times(1)
        .WillOnce(make_send_reply_action());
    inbound_request_dispatcher_->on_message_received(sender_addr, init_upload_msg);

    thread_pool_->process_all_jobs();

    for (auto it = file_content.cbegin(); it != file_content.cend();
         std::advance(it, max_chunk_size_))
    {
        UploadMessage upload_msg;
        upload_msg.request_id = next_request_id++;
        upload_msg.offer_id   = 10;
        upload_msg.offset     = PartSize(std::distance(file_content.cbegin(), it));
        upload_msg.data.resize(max_chunk_size_);
        std::copy_n(it, max_chunk_size_, upload_msg.data.begin());
        EXPECT_CALL(*protocol_message_handler_,
            send_reply(sender_addr,
                ResultOf([](auto &&ptr) { return ptr.get(); },
                    Pointee(AllOf(Field(&BasicReply::request_message_code, MessageCode::UPLOAD),
                        Field(&BasicReply::status_code, StatusCode::OK),
                        Field(&BasicReply::request_id, upload_msg.request_id))))))
            .Times(1)
            .WillOnce(make_send_reply_action());
        EXPECT_CALL(*temporary_data_storage_,
            write(temp_storage_handle, upload_msg.offset, max_chunk_size_, _))
            .With(Args<3, 2>(ElementsAreArray(upload_msg.data.begin(), upload_msg.data.end())))
            .Times(1)
            .WillOnce(Return(true));
        EXPECT_CALL(*protocol_message_handler_,
            send(lift_proxy_addr,
                ResultOf([](auto &&ptr) { return ptr.get(); },
                    WhenDynamicCastTo<UploadMessage *>(
                        Pointee(AllOf(Field(&UploadMessage::offer_id, upload_msg.offer_id),
                            Field(&UploadMessage::offset, upload_msg.offset),
                            Field(&UploadMessage::data, ContainerEq(upload_msg.data))))))))
            .Times(1)
            .WillOnce(make_send_message_action(StatusCode::OK));
        inbound_request_dispatcher_->on_message_received(sender_addr, upload_msg);
    }

    thread_pool_->process_all_jobs();

    int current_read_chunk_idx = 0;
    EXPECT_CALL(*temporary_data_storage_, read_next_chunk(read_handle, max_chunk_size_, _, _, _))
        .Times(number_of_chunks + 1)
        .WillRepeatedly([&](TemporaryDataStorage::ReadHandle *, size_t /*max_amount*/,
                            size_t &offset, size_t &amount, uint8_t *data) {
            if (current_read_chunk_idx == number_of_chunks)
            {
                return false;
            }
            offset  = size_t(current_read_chunk_idx) * max_chunk_size_;
            amount  = max_chunk_size_;
            auto it = file_content.cbegin();
            std::advance(it, offset);
            std::copy_n(it, amount, data);
            ++current_read_chunk_idx;
            return true;
        });

    InitDownloadMessage init_download_msg;
    init_download_msg.request_id = next_request_id++;
    init_download_msg.offer_id   = 10;
    EXPECT_CALL(*protocol_message_handler_,
        send_reply(lift_proxy_addr,
            ResultOf([](auto &&ptr) { return ptr.get(); },
                Pointee(AllOf(Field(&BasicReply::request_message_code, MessageCode::INITDOWNLOAD),
                    Field(&BasicReply::status_code, StatusCode::OK),
                    Field(&BasicReply::request_id, init_download_msg.request_id))))))
        .Times(1)
        .WillOnce(make_send_reply_action());
    inbound_request_dispatcher_->on_message_received(lift_proxy_addr, init_download_msg);

    thread_pool_->process_all_jobs();
}

TEST_F(FileTransferFlowTest, DropPoint_Mixed)
{
    const int         number_of_chunks = 3;
    const auto        part_size        = PartSize(max_chunk_size_ * size_t(number_of_chunks));
    const IPv4Address sender_addr {conversion::to_ipv4_address("69.69.69.69")};
    const IPv4Address lift_proxy_addr {conversion::to_ipv4_address("69.69.69.70")};
    const TemporaryDataStorage::Handle temp_storage_handle = 666;
    const auto read_handle = reinterpret_cast<TemporaryDataStorage::ReadHandle *>(420);

    std::vector<uint8_t> file_content(part_size), received_file_content(part_size);
    std::generate(file_content.begin(), file_content.end(), [&] { return rng_.next<uint8_t>(); });

    ON_CALL(*temporary_data_storage_, create(part_size)).WillByDefault(Return(temp_storage_handle));
    ON_CALL(*temporary_data_storage_, start_reading(temp_storage_handle))
        .WillByDefault(Return(read_handle));
    ON_CALL(*temporary_data_storage_, cancel_reading(read_handle)).WillByDefault(Return(true));

    int current_read_chunk_idx = 0;
    EXPECT_CALL(*temporary_data_storage_, read_next_chunk(read_handle, max_chunk_size_, _, _, _))
        .Times(2)
        .WillRepeatedly([&](TemporaryDataStorage::ReadHandle *, size_t /*max_amount*/,
                            size_t &offset, size_t &amount, uint8_t *data) {
            if (current_read_chunk_idx == 1)
            {
                return false;
            }
            offset  = size_t(current_read_chunk_idx) * max_chunk_size_;
            amount  = max_chunk_size_;
            auto it = file_content.cbegin();
            std::advance(it, offset);
            std::copy_n(it, amount, data);
            ++current_read_chunk_idx;
            return true;
        });

    auto flow = make_flow();
    flow->start();

    RequestId next_request_id = 1;

    RequestDropPointMessage request_drop_point_msg;
    request_drop_point_msg.request_id = next_request_id++;
    request_drop_point_msg.part_size  = part_size;
    EXPECT_CALL(*protocol_message_handler_,
        send_reply(sender_addr,
            ResultOf([](auto &&ptr) { return ptr.get(); },
                Pointee(
                    AllOf(Field(&BasicReply::request_message_code, MessageCode::REQUESTDROPPOINT),
                        Field(&BasicReply::status_code, StatusCode::OK),
                        Field(&BasicReply::request_id, request_drop_point_msg.request_id))))))
        .Times(1)
        .WillOnce(make_send_reply_action());
    inbound_request_dispatcher_->on_message_received(sender_addr, request_drop_point_msg);

    thread_pool_->process_all_jobs();

    InitUploadMessage init_upload_msg;
    init_upload_msg.request_id = next_request_id++;
    init_upload_msg.offer_id   = 10;
    EXPECT_CALL(*protocol_message_handler_,
        send_reply(sender_addr,
            ResultOf([](auto &&ptr) { return ptr.get(); },
                Pointee(AllOf(Field(&BasicReply::request_message_code, MessageCode::INITUPLOAD),
                    Field(&BasicReply::status_code, StatusCode::OK),
                    Field(&BasicReply::request_id, init_upload_msg.request_id))))))
        .Times(1)
        .WillOnce(make_send_reply_action());
    inbound_request_dispatcher_->on_message_received(sender_addr, init_upload_msg);

    thread_pool_->process_all_jobs();

    bool init_download_sent = false;
    for (auto it = file_content.cbegin(); it != file_content.cend();
         std::advance(it, max_chunk_size_))
    {
        UploadMessage upload_msg;
        upload_msg.request_id = next_request_id++;
        upload_msg.offer_id   = 10;
        upload_msg.offset     = PartSize(std::distance(file_content.cbegin(), it));
        upload_msg.data.resize(max_chunk_size_);
        std::copy_n(it, max_chunk_size_, upload_msg.data.begin());
        EXPECT_CALL(*protocol_message_handler_,
            send_reply(sender_addr,
                ResultOf([](auto &&ptr) { return ptr.get(); },
                    Pointee(AllOf(Field(&BasicReply::request_message_code, MessageCode::UPLOAD),
                        Field(&BasicReply::status_code, StatusCode::OK),
                        Field(&BasicReply::request_id, upload_msg.request_id))))))
            .Times(1)
            .WillOnce(make_send_reply_action());
        EXPECT_CALL(*protocol_message_handler_,
            send(lift_proxy_addr,
                ResultOf([](auto &&ptr) { return ptr.get(); },
                    WhenDynamicCastTo<UploadMessage *>(
                        Pointee(AllOf(Field(&UploadMessage::offer_id, upload_msg.offer_id),
                            Field(&UploadMessage::offset, upload_msg.offset),
                            Field(&UploadMessage::data, ContainerEq(upload_msg.data))))))))
            .Times(1)
            .WillOnce(make_send_message_action(StatusCode::OK));

        if (!init_download_sent)
        {
            EXPECT_CALL(*temporary_data_storage_,
                write(temp_storage_handle, upload_msg.offset, max_chunk_size_, _))
                .With(Args<3, 2>(ElementsAreArray(upload_msg.data.begin(), upload_msg.data.end())))
                .Times(1)
                .WillOnce(Return(true));
        }

        inbound_request_dispatcher_->on_message_received(sender_addr, upload_msg);

        if (!init_download_sent)
        {
            thread_pool_->process_all_jobs();

            InitDownloadMessage init_download_msg;
            init_download_msg.request_id = next_request_id++;
            init_download_msg.offer_id   = 10;
            EXPECT_CALL(*protocol_message_handler_,
                send_reply(lift_proxy_addr,
                    ResultOf([](auto &&ptr) { return ptr.get(); },
                        Pointee(AllOf(
                            Field(&BasicReply::request_message_code, MessageCode::INITDOWNLOAD),
                            Field(&BasicReply::status_code, StatusCode::OK),
                            Field(&BasicReply::request_id, init_download_msg.request_id))))))
                .Times(1)
                .WillOnce(make_send_reply_action());
            inbound_request_dispatcher_->on_message_received(lift_proxy_addr, init_download_msg);

            thread_pool_->process_all_jobs();
            init_download_sent = true;
        }
    }

    thread_pool_->process_all_jobs();
}

TEST_F(FileTransferFlowTest, LiftProxy)
{
    const int         number_of_chunks = 3;
    const auto        part_size        = PartSize(max_chunk_size_ * size_t(number_of_chunks));
    const IPv4Address receiver_addr {conversion::to_ipv4_address("69.69.69.69")};
    const IPv4Address drop_point_addr {conversion::to_ipv4_address("69.69.69.70")};

    std::vector<uint8_t> file_content(part_size), received_file_content(part_size);
    std::generate(file_content.begin(), file_content.end(), [&] { return rng_.next<uint8_t>(); });

    auto flow = make_flow();
    flow->start();

    RequestId next_request_id = 1;

    RequestLiftProxyMessage request_lift_proxy_msg;
    request_lift_proxy_msg.request_id = next_request_id++;
    request_lift_proxy_msg.part_size  = part_size;
    EXPECT_CALL(*protocol_message_handler_,
        send_reply(receiver_addr,
            ResultOf([](auto &&ptr) { return ptr.get(); },
                Pointee(
                    AllOf(Field(&BasicReply::request_message_code, MessageCode::REQUESTLIFTPROXY),
                        Field(&BasicReply::status_code, StatusCode::OK),
                        Field(&BasicReply::request_id, request_lift_proxy_msg.request_id))))))
        .Times(1)
        .WillOnce(make_send_reply_action());
    inbound_request_dispatcher_->on_message_received(receiver_addr, request_lift_proxy_msg);

    thread_pool_->process_all_jobs();

    FetchMessage fetch_msg;
    fetch_msg.request_id = next_request_id++;
    fetch_msg.offer_id   = 10;
    fetch_msg.drop_point = drop_point_addr;
    EXPECT_CALL(*protocol_message_handler_,
        send_reply(receiver_addr,
            ResultOf([](auto &&ptr) { return ptr.get(); },
                Pointee(AllOf(Field(&BasicReply::request_message_code, MessageCode::FETCH),
                    Field(&BasicReply::status_code, StatusCode::OK),
                    Field(&BasicReply::request_id, fetch_msg.request_id))))))
        .Times(1)
        .WillOnce(make_send_reply_action());
    EXPECT_CALL(*protocol_message_handler_,
        send(drop_point_addr, ResultOf([](auto &&ptr) { return ptr.get(); },
                                  WhenDynamicCastTo<InitDownloadMessage *>(Pointee(
                                      Field(&InitDownloadMessage::offer_id, fetch_msg.offer_id))))))
        .Times(1)
        .WillOnce(make_send_message_action(StatusCode::OK));

    inbound_request_dispatcher_->on_message_received(receiver_addr, fetch_msg);
    thread_pool_->process_all_jobs();

    for (auto it = file_content.cbegin(); it != file_content.cend();
         std::advance(it, max_chunk_size_))
    {
        UploadMessage upload_msg;
        upload_msg.request_id = next_request_id++;
        upload_msg.offer_id   = 10;
        upload_msg.offset     = PartSize(std::distance(file_content.cbegin(), it));
        upload_msg.data.resize(max_chunk_size_);
        std::copy_n(it, max_chunk_size_, upload_msg.data.begin());
        EXPECT_CALL(*protocol_message_handler_,
            send_reply(drop_point_addr,
                ResultOf([](auto &&ptr) { return ptr.get(); },
                    Pointee(AllOf(Field(&BasicReply::request_message_code, MessageCode::UPLOAD),
                        Field(&BasicReply::status_code, StatusCode::OK),
                        Field(&BasicReply::request_id, upload_msg.request_id))))))
            .Times(1)
            .WillOnce(make_send_reply_action());
        EXPECT_CALL(*protocol_message_handler_,
            send(receiver_addr,
                ResultOf([](auto &&ptr) { return ptr.get(); },
                    WhenDynamicCastTo<UploadMessage *>(
                        Pointee(AllOf(Field(&UploadMessage::offer_id, upload_msg.offer_id),
                            Field(&UploadMessage::offset, upload_msg.offset),
                            Field(&UploadMessage::data, ContainerEq(upload_msg.data))))))))
            .Times(1)
            .WillOnce(make_send_message_action(StatusCode::OK));
        inbound_request_dispatcher_->on_message_received(drop_point_addr, upload_msg);
    }

    thread_pool_->process_all_jobs();
}
