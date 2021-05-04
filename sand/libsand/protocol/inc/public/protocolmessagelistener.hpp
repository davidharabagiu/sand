#ifndef SAND_PROTOCOL_PROTOCOLMESSAGELISTENER_HPP_
#define SAND_PROTOCOL_PROTOCOLMESSAGELISTENER_HPP_

#include "address.hpp"
#include "messages.hpp

namespace sand::protocol
{
class ProtocolMessageListener
{
public:
    virtual ~ProtocolMessageListener() = default;

    virtual void on_message_received(Address from, const PullMessagePayload &message)     = 0;
    virtual void on_message_received(Address from, const PushMessage &message)            = 0;
    virtual void on_message_received(Address from, const ByeMessage &message)             = 0;
    virtual void on_message_received(Address from, const DeadMessage &message)            = 0;
    virtual void on_message_received(Address from, const PingMessage &message)            = 0;
    virtual void on_message_received(Address from, const DNLSyncMessage &message)         = 0;
    virtual void on_message_received(Address from, const SearchMessage &message)          = 0;
    virtual void on_message_received(Address from, const OfferMessage &message)           = 0;
    virtual void on_message_received(Address from, const UncacheMessage &message)         = 0;
    virtual void on_message_received(Address from, const ConfirmTransferMessage &message) = 0;
    virtual void on_message_received(Address from, const RequestProxyMessage &message)    = 0;
    virtual void on_message_received(Address from, const InitUploadMessage &message)      = 0;
    virtual void on_message_received(Address from, const UploadMessage &message)          = 0;
    virtual void on_message_received(Address from, const FetchMessage &message)           = 0;
    virtual void on_message_received(Address from, const InitDownloadMessage &message)    = 0;
};
}  // namespace sand::protocol

#endif  // SAND_PROTOCOL_PROTOCOLMESSAGELISTENER_HPP_
