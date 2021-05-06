#ifndef SAND_PROTOCOLTEST_REQUESTDESERIALIZATIONRESULTRECEPTOR_MOCK_HPP_
#define SAND_PROTOCOLTEST_REQUESTDESERIALIZATIONRESULTRECEPTOR_MOCK_HPP_

#include <gmock/gmock.h>

#include "messages.hpp"
#include "requestdeserializationresultreceptor.hpp"

using namespace sand::protocol;

class RequestDeserializationResultReceptorMock : public RequestDeserializationResultReceptor
{
public:
    MOCK_METHOD(void, deserialized, (const PullMessage &), (override));
    MOCK_METHOD(void, deserialized, (const PushMessage &), (override));
    MOCK_METHOD(void, deserialized, (const ByeMessage &), (override));
    MOCK_METHOD(void, deserialized, (const DeadMessage &), (override));
    MOCK_METHOD(void, deserialized, (const PingMessage &), (override));
    MOCK_METHOD(void, deserialized, (const DNLSyncMessage &), (override));
    MOCK_METHOD(void, deserialized, (const SearchMessage &), (override));
    MOCK_METHOD(void, deserialized, (const OfferMessage &), (override));
    MOCK_METHOD(void, deserialized, (const UncacheMessage &), (override));
    MOCK_METHOD(void, deserialized, (const ConfirmTransferMessage &), (override));
    MOCK_METHOD(void, deserialized, (const RequestProxyMessage &), (override));
    MOCK_METHOD(void, deserialized, (const InitUploadMessage &), (override));
    MOCK_METHOD(void, deserialized, (const UploadMessage &), (override));
    MOCK_METHOD(void, deserialized, (const FetchMessage &), (override));
    MOCK_METHOD(void, deserialized, (const InitDownloadMessage &), (override));
    MOCK_METHOD(void, deserialized, (const BasicReply &), (override));
    MOCK_METHOD(void, deserialized, (const PullReply &), (override));
    MOCK_METHOD(void, error, (), (override));
};

#endif  // SAND_PROTOCOLTEST_REQUESTDESERIALIZATIONRESULTRECEPTOR_MOCK_HPP_
