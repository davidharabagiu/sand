#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <sstream>
#include <string>
#include <type_traits>
#include <utility>

#include "messageserializerimpl.hpp"

#include "requestdeserializationresultreceptor_mock.hpp"

using namespace ::testing;
using namespace ::sand::protocol;
using namespace ::sand::network;

namespace
{
class MessageSerializerTest : public Test
{
protected:
    void SetUp() override
    {
        std::srand(unsigned(std::time(nullptr)));
        result_receptor_mock_ =
            std::make_unique<NiceMock<RequestDeserializationResultReceptorMock>>();
    }

    static IPv4Address to_ipv4_addr(const std::string &str)
    {
        std::istringstream ss {str};
        IPv4Address        result = 0;
        for (int i = 0; i != 4; ++i)
        {
            IPv4Address byte;
            ss >> byte;
            ss.get();
            result <<= 8;
            result |= byte;
        }
        return result;
    }

    template<typename OutputIt, typename Int = std::decay_t<decltype(*std::declval<OutputIt>())>>
    static auto random_values(OutputIt dst, size_t count)
        -> std::enable_if_t<std::is_integral_v<Int>>
    {
        while (count--)
        {
            *dst++ = Int(std::rand());
        }
    }

    std::unique_ptr<RequestDeserializationResultReceptorMock> result_receptor_mock_;
};
}  // namespace

TEST_F(MessageSerializerTest, SerializeRequest_Pull)
{
    PullMessage req;
    req.request_id    = 1;
    req.address_count = 5;
    std::vector<uint8_t> expected {0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05};

    MessageSerializerImpl serializer;
    auto                  bytes = serializer.serialize(req);

    EXPECT_EQ(bytes, expected);
}

TEST_F(MessageSerializerTest, SerializeRequest_Push)
{
    PushMessage req;
    req.request_id = 2;
    std::vector<uint8_t> expected {0x21, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    MessageSerializerImpl serializer;
    auto                  bytes = serializer.serialize(req);

    EXPECT_EQ(bytes, expected);
}

TEST_F(MessageSerializerTest, SerializeRequest_Bye)
{
    ByeMessage req;
    req.request_id = 3;
    std::vector<uint8_t> expected {0x22, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    MessageSerializerImpl serializer;
    auto                  bytes = serializer.serialize(req);

    EXPECT_EQ(bytes, expected);
}

TEST_F(MessageSerializerTest, SerializeRequest_Dead)
{
    DeadMessage req;
    req.request_id = 4;
    req.nodes      = {
        to_ipv4_addr("192.168.0.1"), to_ipv4_addr("192.168.0.2"), to_ipv4_addr("192.168.0.3")};
    std::vector<uint8_t> expected {0x23, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x01,
        0x00, 0xa8, 0xc0, 0x02, 0x00, 0xa8, 0xc0, 0x03, 0x00, 0xa8, 0xc0};

    MessageSerializerImpl serializer;
    auto                  bytes = serializer.serialize(req);

    EXPECT_EQ(bytes, expected);
}

TEST_F(MessageSerializerTest, SerializeRequest_Ping)
{
    PingMessage req;
    req.request_id = 5;
    std::vector<uint8_t> expected {0x24, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    MessageSerializerImpl serializer;
    auto                  bytes = serializer.serialize(req);

    EXPECT_EQ(bytes, expected);
}

TEST_F(MessageSerializerTest, SerializeRequest_DNLSync)
{
    using namespace std::chrono;

    DNLSyncMessage req;
    req.request_id = 6;
    req.entries    = {{Timestamp {milliseconds {1620294550000}}, to_ipv4_addr("192.168.0.1"),
                       DNLSyncMessage::Entry::ADD_ADDRESS},
        {Timestamp {milliseconds {1620296660000}}, to_ipv4_addr("192.168.0.2"),
            DNLSyncMessage::Entry::REMOVE_ADDRESS}};

    std::vector<uint8_t> expected {0x25, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xf0,
        0xc1, 0x14, 0x41, 0x79, 0x01, 0x00, 0x00, 0x01, 0x00, 0xa8, 0xc0, 0x00, 0x20, 0xf4, 0x34,
        0x41, 0x79, 0x01, 0x00, 0x00, 0x02, 0x00, 0xa8, 0xc0, 0x01};

    MessageSerializerImpl serializer;
    auto                  bytes = serializer.serialize(req);

    EXPECT_EQ(bytes, expected);
}

TEST_F(MessageSerializerTest, SerializeRequest_Search)
{
    SearchMessage req;
    req.request_id = 7;
    req.search_id  = 0x19c5d0b4db434a14;
    random_values(req.sender_public_key.begin(), req.sender_public_key.size());
    random_values(req.file_hash.begin(), req.file_hash.size());

    std::vector<uint8_t> expected {0x40, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x4a,
        0x43, 0xdb, 0xb4, 0xd0, 0xc5, 0x19};
    std::copy(
        req.sender_public_key.cbegin(), req.sender_public_key.cend(), std::back_inserter(expected));
    std::copy(req.file_hash.cbegin(), req.file_hash.cend(), std::back_inserter(expected));

    MessageSerializerImpl serializer;
    auto                  bytes = serializer.serialize(req);

    EXPECT_EQ(bytes, expected);
}

TEST_F(MessageSerializerTest, SerializeRequest_Uncache)
{
    UncacheMessage req;
    req.request_id = 8;
    random_values(req.file_hash.begin(), req.file_hash.size());

    std::vector<uint8_t> expected {0x42, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    std::copy(req.file_hash.cbegin(), req.file_hash.cend(), std::back_inserter(expected));

    MessageSerializerImpl serializer;
    auto                  bytes = serializer.serialize(req);

    EXPECT_EQ(bytes, expected);
}

TEST_F(MessageSerializerTest, SerializeRequest_ConfirmTransfer)
{
    ConfirmTransferMessage req;
    req.request_id = 9;
    req.offer_id   = 0x198971b3068d7e4d;
    std::vector<uint8_t> expected {0x43, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4d, 0x7e,
        0x8d, 0x06, 0xb3, 0x71, 0x89, 0x19};

    MessageSerializerImpl serializer;
    auto                  bytes = serializer.serialize(req);

    EXPECT_EQ(bytes, expected);
}

TEST_F(MessageSerializerTest, SerializeRequest_RequestProxy)
{
    RequestProxyMessage req;
    req.request_id = 10;
    req.part_size  = 0xabb355d;
    std::vector<uint8_t> expected {
        0x60, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5d, 0x35, 0xbb, 0x0a};

    MessageSerializerImpl serializer;
    auto                  bytes = serializer.serialize(req);

    EXPECT_EQ(bytes, expected);
}

TEST_F(MessageSerializerTest, SerializeRequest_InitUpload)
{
    InitUploadMessage req;
    req.request_id = 11;
    req.offer_id   = 0x198971b3068d7e4d;
    std::vector<uint8_t> expected {0x62, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4d, 0x7e,
        0x8d, 0x06, 0xb3, 0x71, 0x89, 0x19};

    MessageSerializerImpl serializer;
    auto                  bytes = serializer.serialize(req);

    EXPECT_EQ(bytes, expected);
}

TEST_F(MessageSerializerTest, SerializeRequest_Upload)
{
    UploadMessage req;
    req.request_id = 12;
    req.offset     = 0x90020526;
    req.data.resize(0x400000);
    random_values(req.data.begin(), req.data.size());

    std::vector<uint8_t> expected {0x63, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x26, 0x05,
        0x02, 0x90, 0x00, 0x00, 0x40, 0x00};
    std::copy(req.data.cbegin(), req.data.cend(), std::back_inserter(expected));

    MessageSerializerImpl serializer;
    auto                  bytes = serializer.serialize(req);

    EXPECT_EQ(bytes, expected);
}

TEST_F(MessageSerializerTest, SerializeRequest_Fetch)
{
    FetchMessage req;
    req.request_id = 13;
    req.offer_id   = 0x198971b3068d7e4d;
    req.drop_point = to_ipv4_addr("192.168.0.1");
    std::vector<uint8_t> expected {0x64, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4d, 0x7e,
        0x8d, 0x06, 0xb3, 0x71, 0x89, 0x19, 0x01, 0x00, 0xa8, 0xc0};

    MessageSerializerImpl serializer;
    auto                  bytes = serializer.serialize(req);

    EXPECT_EQ(bytes, expected);
}

TEST_F(MessageSerializerTest, SerializeRequest_InitDownload)
{
    InitDownloadMessage req;
    req.request_id = 14;
    req.offer_id   = 0x198971b3068d7e4d;
    std::vector<uint8_t> expected {0x65, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4d, 0x7e,
        0x8d, 0x06, 0xb3, 0x71, 0x89, 0x19};

    MessageSerializerImpl serializer;
    auto                  bytes = serializer.serialize(req);

    EXPECT_EQ(bytes, expected);
}

TEST_F(MessageSerializerTest, SerializeReply_Basic)
{
    BasicReply reply {RequestCode::PING};
    reply.request_id  = 15;
    reply.status_code = StatusCode::UNREACHABLE;
    std::vector<uint8_t> expected {
        0xff, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x24};

    MessageSerializerImpl serializer;
    auto                  bytes = serializer.serialize(reply);

    EXPECT_EQ(bytes, expected);
}

TEST_F(MessageSerializerTest, SerializeReply_Pull)
{
    PullReply reply;
    reply.request_id  = 16;
    reply.status_code = StatusCode::OK;
    reply.peers       = {
        to_ipv4_addr("192.168.0.1"), to_ipv4_addr("192.168.0.2"), to_ipv4_addr("192.168.0.3")};
    std::vector<uint8_t> expected {0xff, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20,
        0x03, 0x01, 0x00, 0xa8, 0xc0, 0x02, 0x00, 0xa8, 0xc0, 0x03, 0x00, 0xa8, 0xc0};

    MessageSerializerImpl serializer;
    auto                  bytes = serializer.serialize(reply);

    EXPECT_EQ(bytes, expected);
}

TEST_F(MessageSerializerTest, DeserializeRequest_Pull)
{
    std::vector<uint8_t> bytes {0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05};

    MessageSerializerImpl serializer;
    EXPECT_CALL(*result_receptor_mock_,
        deserialized(
            Matcher<const PullMessage &>(AllOf(Field(&PullMessage::request_code, RequestCode::PULL),
                Field(&PullMessage::request_id, 1), Field(&PullMessage::address_count, 5)))))
        .Times(1);

    serializer.deserialize(bytes, *result_receptor_mock_);
}

TEST_F(MessageSerializerTest, DeserializeRequest_Push)
{
    std::vector<uint8_t> bytes {0x21, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    MessageSerializerImpl serializer;
    EXPECT_CALL(*result_receptor_mock_, deserialized(Matcher<const PushMessage &>(AllOf(
                                            Field(&PushMessage::request_code, RequestCode::PUSH),
                                            Field(&PushMessage::request_id, 2)))))
        .Times(1);

    serializer.deserialize(bytes, *result_receptor_mock_);
}

TEST_F(MessageSerializerTest, DeserializeRequest_Bye)
{
    std::vector<uint8_t> bytes {0x22, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    MessageSerializerImpl serializer;
    EXPECT_CALL(*result_receptor_mock_, deserialized(Matcher<const ByeMessage &>(AllOf(
                                            Field(&ByeMessage::request_code, RequestCode::BYE),
                                            Field(&ByeMessage::request_id, 3)))))
        .Times(1);

    serializer.deserialize(bytes, *result_receptor_mock_);
}

TEST_F(MessageSerializerTest, DeserializeRequest_Dead)
{
    std::vector<IPv4Address> nodes {
        to_ipv4_addr("192.168.0.1"), to_ipv4_addr("192.168.0.2"), to_ipv4_addr("192.168.0.3")};

    std::vector<uint8_t> bytes {0x23, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x01,
        0x00, 0xa8, 0xc0, 0x02, 0x00, 0xa8, 0xc0, 0x03, 0x00, 0xa8, 0xc0};

    MessageSerializerImpl serializer;
    EXPECT_CALL(*result_receptor_mock_,
        deserialized(
            Matcher<const DeadMessage &>(AllOf(Field(&DeadMessage::request_code, RequestCode::DEAD),
                Field(&DeadMessage::request_id, 4), Field(&DeadMessage::nodes, nodes)))))
        .Times(1);

    serializer.deserialize(bytes, *result_receptor_mock_);
}

TEST_F(MessageSerializerTest, DeserializeRequest_Ping)
{
    std::vector<uint8_t> bytes {0x24, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    MessageSerializerImpl serializer;
    EXPECT_CALL(*result_receptor_mock_, deserialized(Matcher<const PingMessage &>(AllOf(
                                            Field(&PingMessage::request_code, RequestCode::PING),
                                            Field(&PingMessage::request_id, 5)))))
        .Times(1);

    serializer.deserialize(bytes, *result_receptor_mock_);
}

MATCHER(DNLSyncEntryEq, "")
{
    return std::get<0>(arg).timestamp == std::get<1>(arg).timestamp &&
           std::get<0>(arg).address == std::get<1>(arg).address &&
           std::get<0>(arg).action == std::get<1>(arg).action;
}

TEST_F(MessageSerializerTest, DeserializeRequest_DNLSync)
{
    using namespace std::chrono;

    std::vector<DNLSyncMessage::Entry> entries {
        {Timestamp {milliseconds {1620294550000}}, to_ipv4_addr("192.168.0.1"),
            DNLSyncMessage::Entry::ADD_ADDRESS},
        {Timestamp {milliseconds {1620296660000}}, to_ipv4_addr("192.168.0.2"),
            DNLSyncMessage::Entry::REMOVE_ADDRESS}};

    std::vector<uint8_t> bytes {0x25, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xf0,
        0xc1, 0x14, 0x41, 0x79, 0x01, 0x00, 0x00, 0x01, 0x00, 0xa8, 0xc0, 0x00, 0x20, 0xf4, 0x34,
        0x41, 0x79, 0x01, 0x00, 0x00, 0x02, 0x00, 0xa8, 0xc0, 0x01};

    MessageSerializerImpl serializer;
    EXPECT_CALL(*result_receptor_mock_,
        deserialized(Matcher<const DNLSyncMessage &>(
            AllOf(Field(&DNLSyncMessage::request_code, RequestCode::DNLSYNC),
                Field(&DNLSyncMessage::request_id, 6),
                Field(&DNLSyncMessage::entries, Pointwise(DNLSyncEntryEq(), entries))))))
        .Times(1);

    serializer.deserialize(bytes, *result_receptor_mock_);
}

TEST_F(MessageSerializerTest, DeserializeRequest_Search)
{
    SearchId      search_id = 0x19c5d0b4db434a14;
    NodePublicKey pub_key;
    AHash         file_hash;
    random_values(pub_key.begin(), pub_key.size());
    random_values(file_hash.begin(), file_hash.size());

    std::vector<uint8_t> bytes {0x40, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x4a,
        0x43, 0xdb, 0xb4, 0xd0, 0xc5, 0x19};
    std::copy(pub_key.cbegin(), pub_key.cend(), std::back_inserter(bytes));
    std::copy(file_hash.cbegin(), file_hash.cend(), std::back_inserter(bytes));

    MessageSerializerImpl serializer;
    EXPECT_CALL(*result_receptor_mock_,
        deserialized(Matcher<const SearchMessage &>(
            AllOf(Field(&SearchMessage::request_code, RequestCode::SEARCH),
                Field(&SearchMessage::request_id, 7), Field(&SearchMessage::search_id, search_id),
                Field(&SearchMessage::sender_public_key, pub_key),
                Field(&SearchMessage::file_hash, file_hash)))))
        .Times(1);

    serializer.deserialize(bytes, *result_receptor_mock_);
}

TEST_F(MessageSerializerTest, DeserializeRequest_Uncache)
{
    AHash file_hash;
    random_values(file_hash.begin(), file_hash.size());

    std::vector<uint8_t> bytes {0x42, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    std::copy(file_hash.cbegin(), file_hash.cend(), std::back_inserter(bytes));

    MessageSerializerImpl serializer;
    EXPECT_CALL(*result_receptor_mock_,
        deserialized(Matcher<const UncacheMessage &>(AllOf(
            Field(&UncacheMessage::request_code, RequestCode::UNCACHE),
            Field(&UncacheMessage::request_id, 8), Field(&UncacheMessage::file_hash, file_hash)))))
        .Times(1);

    serializer.deserialize(bytes, *result_receptor_mock_);
}

TEST_F(MessageSerializerTest, DeserializeRequest_ConfirmTransfer)
{
    OfferId              offer_id = 0x198971b3068d7e4d;
    std::vector<uint8_t> bytes {0x43, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4d, 0x7e,
        0x8d, 0x06, 0xb3, 0x71, 0x89, 0x19};

    MessageSerializerImpl serializer;
    EXPECT_CALL(*result_receptor_mock_,
        deserialized(Matcher<const ConfirmTransferMessage &>(
            AllOf(Field(&ConfirmTransferMessage::request_code, RequestCode::CONFIRMTRANSFER),
                Field(&ConfirmTransferMessage::request_id, 9),
                Field(&ConfirmTransferMessage::offer_id, offer_id)))))
        .Times(1);

    serializer.deserialize(bytes, *result_receptor_mock_);
}

TEST_F(MessageSerializerTest, DeserializeRequest_RequestProxy)
{
    PartSize             part_size = 0xabb355d;
    std::vector<uint8_t> bytes {
        0x60, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5d, 0x35, 0xbb, 0x0a};

    MessageSerializerImpl serializer;
    EXPECT_CALL(*result_receptor_mock_,
        deserialized(Matcher<const RequestProxyMessage &>(
            AllOf(Field(&RequestProxyMessage::request_code, RequestCode::REQUESTPROXY),
                Field(&RequestProxyMessage::request_id, 10),
                Field(&RequestProxyMessage::part_size, part_size)))))
        .Times(1);

    serializer.deserialize(bytes, *result_receptor_mock_);
}

TEST_F(MessageSerializerTest, DeserializeRequest_InitUpload)
{
    OfferId              offer_id = 0x198971b3068d7e4d;
    std::vector<uint8_t> bytes {0x62, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4d, 0x7e,
        0x8d, 0x06, 0xb3, 0x71, 0x89, 0x19};

    MessageSerializerImpl serializer;
    EXPECT_CALL(*result_receptor_mock_,
        deserialized(Matcher<const InitUploadMessage &>(
            AllOf(Field(&InitUploadMessage::request_code, RequestCode::INITUPLOAD),
                Field(&InitUploadMessage::request_id, 11),
                Field(&InitUploadMessage::offer_id, offer_id)))))
        .Times(1);

    serializer.deserialize(bytes, *result_receptor_mock_);
}

TEST_F(MessageSerializerTest, DeserializeRequest_Upload)
{
    PartSize             offset = 0x90020526;
    std::vector<uint8_t> data(0x400000);
    random_values(data.begin(), data.size());

    std::vector<uint8_t> bytes {0x63, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x26, 0x05,
        0x02, 0x90, 0x00, 0x00, 0x40, 0x00};
    std::copy(data.cbegin(), data.cend(), std::back_inserter(bytes));

    MessageSerializerImpl serializer;
    EXPECT_CALL(*result_receptor_mock_,
        deserialized(Matcher<const UploadMessage &>(
            AllOf(Field(&UploadMessage::request_code, RequestCode::UPLOAD),
                Field(&UploadMessage::request_id, 12), Field(&UploadMessage::offset, offset),
                Field(&UploadMessage::data, data)))))
        .Times(1);

    serializer.deserialize(bytes, *result_receptor_mock_);
}

TEST_F(MessageSerializerTest, DeserializeRequest_Fetch)
{
    OfferId              offer_id   = 0x198971b3068d7e4d;
    IPv4Address          drop_point = to_ipv4_addr("192.168.0.1");
    std::vector<uint8_t> bytes {0x64, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4d, 0x7e,
        0x8d, 0x06, 0xb3, 0x71, 0x89, 0x19, 0x01, 0x00, 0xa8, 0xc0};

    MessageSerializerImpl serializer;
    EXPECT_CALL(*result_receptor_mock_,
        deserialized(Matcher<const FetchMessage &>(
            AllOf(Field(&FetchMessage::request_code, RequestCode::FETCH),
                Field(&FetchMessage::request_id, 13), Field(&FetchMessage::offer_id, offer_id),
                Field(&FetchMessage::drop_point, drop_point)))))
        .Times(1);

    serializer.deserialize(bytes, *result_receptor_mock_);
}

TEST_F(MessageSerializerTest, DeserializeRequest_InitDownload)
{
    OfferId              offer_id = 0x198971b3068d7e4d;
    std::vector<uint8_t> bytes {0x65, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4d, 0x7e,
        0x8d, 0x06, 0xb3, 0x71, 0x89, 0x19};

    MessageSerializerImpl serializer;
    EXPECT_CALL(*result_receptor_mock_,
        deserialized(Matcher<const InitDownloadMessage &>(
            AllOf(Field(&InitDownloadMessage::request_code, RequestCode::INITDOWNLOAD),
                Field(&InitDownloadMessage::request_id, 14),
                Field(&InitDownloadMessage::offer_id, offer_id)))))
        .Times(1);

    serializer.deserialize(bytes, *result_receptor_mock_);
}

TEST_F(MessageSerializerTest, DeserializeRequest_InvalidRequestCode)
{
    std::vector<uint8_t> bytes {0xfe, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    MessageSerializerImpl serializer;
    EXPECT_CALL(*result_receptor_mock_, error()).Times(1);

    serializer.deserialize(bytes, *result_receptor_mock_);
}

TEST_F(MessageSerializerTest, DeserializeReply_Basic)
{
    std::vector<uint8_t> bytes {0xff, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x24};

    MessageSerializerImpl serializer;
    EXPECT_CALL(*result_receptor_mock_,
        deserialized(
            Matcher<const BasicReply &>(AllOf(Field(&BasicReply::request_code, RequestCode::REPLY),
                Field(&BasicReply::request_id, 16),
                Field(&BasicReply::status_code, StatusCode::UNREACHABLE),
                Field(&BasicReply::source_request_code, RequestCode::PING)))))
        .Times(1);

    serializer.deserialize(bytes, *result_receptor_mock_);
}

TEST_F(MessageSerializerTest, DeserializeReply_Pull)
{
    std::vector<IPv4Address> peers = {
        to_ipv4_addr("192.168.0.1"), to_ipv4_addr("192.168.0.2"), to_ipv4_addr("192.168.0.3")};
    std::vector<uint8_t> bytes {0xff, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20,
        0x03, 0x01, 0x00, 0xa8, 0xc0, 0x02, 0x00, 0xa8, 0xc0, 0x03, 0x00, 0xa8, 0xc0};

    MessageSerializerImpl serializer;
    EXPECT_CALL(*result_receptor_mock_,
        deserialized(
            Matcher<const PullReply &>(AllOf(Field(&PullReply::request_code, RequestCode::REPLY),
                Field(&PullReply::request_id, 17), Field(&PullReply::status_code, StatusCode::OK),
                Field(&PullReply::source_request_code, RequestCode::PULL),
                Field(&PullReply::peers, peers)))))
        .Times(1);

    serializer.deserialize(bytes, *result_receptor_mock_);
}
