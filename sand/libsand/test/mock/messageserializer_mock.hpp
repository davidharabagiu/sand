#ifndef SAND_TEST_MESSAGESERIALIZER_MOCK_HPP_
#define SAND_TEST_MESSAGESERIALIZER_MOCK_HPP_

#include <gmock/gmock.h>

#include "messagedeserializationresultreceptor.hpp"
#include "messages.hpp"
#include "messageserializer.hpp"

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
    MOCK_METHOD(
        std::vector<uint8_t>, serialize, (const RequestDropPointMessage &), (const, override));
    MOCK_METHOD(
        std::vector<uint8_t>, serialize, (const RequestLiftProxyMessage &), (const, override));
    MOCK_METHOD(std::vector<uint8_t>, serialize, (const InitUploadMessage &), (const, override));
    MOCK_METHOD(std::vector<uint8_t>, serialize, (const UploadMessage &), (const, override));
    MOCK_METHOD(std::vector<uint8_t>, serialize, (const FetchMessage &), (const, override));
    MOCK_METHOD(std::vector<uint8_t>, serialize, (const InitDownloadMessage &), (const, override));
    MOCK_METHOD(std::vector<uint8_t>, serialize, (const BasicReply &), (const, override));
    MOCK_METHOD(std::vector<uint8_t>, serialize, (const PullReply &), (const, override));
    MOCK_METHOD(void, deserialize,
        (const std::vector<uint8_t> &, MessageDeserializationResultReceptor &), (const, override));
};

#endif  // SAND_TEST_MESSAGESERIALIZER_MOCK_HPP_
