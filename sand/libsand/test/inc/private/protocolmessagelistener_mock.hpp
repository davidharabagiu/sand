#ifndef SAND_TEST_PROTOCOLMESSAGELISTENER_MOCK_HPP_
#define SAND_TEST_PROTOCOLMESSAGELISTENER_MOCK_HPP_

#include <gmock/gmock.h>

#include "messages.hpp"
#include "protocolmessagelistener.hpp"

using namespace sand::protocol;
using namespace sand::network;

class ProtocolMessageListenerMock : public ProtocolMessageListener
{
public:
    MOCK_METHOD(void, on_message_received, (IPv4Address, const PullMessage &), (override));
    MOCK_METHOD(void, on_message_received, (IPv4Address, const PushMessage &), (override));
    MOCK_METHOD(void, on_message_received, (IPv4Address, const ByeMessage &), (override));
    MOCK_METHOD(void, on_message_received, (IPv4Address, const DeadMessage &), (override));
    MOCK_METHOD(void, on_message_received, (IPv4Address, const PingMessage &), (override));
    MOCK_METHOD(void, on_message_received, (IPv4Address, const DNLSyncMessage &), (override));
    MOCK_METHOD(void, on_message_received, (IPv4Address, const SearchMessage &), (override));
    MOCK_METHOD(void, on_message_received, (IPv4Address, const OfferMessage &), (override));
    MOCK_METHOD(void, on_message_received, (IPv4Address, const UncacheMessage &), (override));
    MOCK_METHOD(
        void, on_message_received, (IPv4Address, const ConfirmTransferMessage &), (override));
    MOCK_METHOD(
        void, on_message_received, (IPv4Address, const RequestDropPointMessage &), (override));
    MOCK_METHOD(
        void, on_message_received, (IPv4Address, const RequestLiftProxyMessage &), (override));
    MOCK_METHOD(void, on_message_received, (IPv4Address, const InitUploadMessage &), (override));
    MOCK_METHOD(void, on_message_received, (IPv4Address, const UploadMessage &), (override));
    MOCK_METHOD(void, on_message_received, (IPv4Address, const FetchMessage &), (override));
    MOCK_METHOD(void, on_message_received, (IPv4Address, const InitDownloadMessage &), (override));
};

#endif  // SAND_TEST_PROTOCOLMESSAGELISTENER_MOCK_HPP_
