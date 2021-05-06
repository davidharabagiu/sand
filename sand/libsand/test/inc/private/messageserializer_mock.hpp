#ifndef SAND_PROTOCOLTEST_MESSAGESERIALIZER_MOCK_HPP_
#define SAND_PROTOCOLTEST_MESSAGESERIALIZER_MOCK_HPP_

#include <gmock/gmock.h>

#include "messages.hpp"
#include "messageserializer.hpp"
#include "requestdeserializationresultreceptor.hpp"

using namespace sand::protocol;

class MessageSerializerMock : public MessageSerializer
{
public:
    MOCK_METHOD(std::vector<uint8_t>, serialize, (const PullMessage &), (const, override));
    MOCK_METHOD(std::vector<uint8_t>, serialize, (const PushMessage &), (const, override));
    MOCK_METHOD(std::vector<uint8_t>, serialize, (const ByeMessage &), (const, override));
    MOCK_METHOD(std::vector<uint8_t>, serialize, (const DeadMessage &), (const, override));
    MOCK_METHOD(std::vector<uint8_t>, serialize, (const PingMessage &), (const, override));
    MOCK_METHOD(std::vector<uint8_t>, serialize, (const DNLSyncMessage &), (const, override));
    MOCK_METHOD(std::vector<uint8_t>, serialize, (const SearchMessage &), (const, override));
    MOCK_METHOD(std::vector<uint8_t>, serialize, (const OfferMessage &), (const, override));
    MOCK_METHOD(std::vector<uint8_t>, serialize, (const UncacheMessage &), (const, override));
    MOCK_METHOD(
        std::vector<uint8_t>, serialize, (const ConfirmTransferMessage &), (const, override));
    MOCK_METHOD(std::vector<uint8_t>, serialize, (const RequestProxyMessage &), (const, override));
    MOCK_METHOD(std::vector<uint8_t>, serialize, (const InitUploadMessage &), (const, override));
    MOCK_METHOD(std::vector<uint8_t>, serialize, (const UploadMessage &), (const, override));
    MOCK_METHOD(std::vector<uint8_t>, serialize, (const FetchMessage &), (const, override));
    MOCK_METHOD(std::vector<uint8_t>, serialize, (const InitDownloadMessage &), (const, override));
    MOCK_METHOD(std::vector<uint8_t>, serialize, (const BasicReply &), (const, override));
    MOCK_METHOD(std::vector<uint8_t>, serialize, (const PullReply &), (const, override));
    MOCK_METHOD(void, deserialize,
        (const std::vector<uint8_t> &, RequestDeserializationResultReceptor &), (const, override));
    MOCK_METHOD(bool, deserialize, (const std::vector<uint8_t> &, BasicReply &), (const, override));
    MOCK_METHOD(bool, deserialize, (const std::vector<uint8_t> &, PullReply &), (const, override));
};

#endif  // SAND_PROTOCOLTEST_MESSAGESERIALIZER_MOCK_HPP_
