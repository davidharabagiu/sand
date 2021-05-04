#ifndef SAND_PROTOCOL_PROTOCOLMESSAGEHANDLER_HPP_
#define SAND_PROTOCOL_PROTOCOLMESSAGEHANDLER_HPP_

#include <future>
#include <memory>
#include <vector>

#include "address.hpp"
#include "messages.hpp"
#include "replies.hpp"

namespace sand::protocol
{
// Forward declarations
class ProtocolMessageListener;

class ProtocolMessageHandler
{
public:
    virtual ~Protocol() = default;
    virtual bool register_message_listener(
        const std::shared_ptr<ProtocolMessageListener> &listener) = 0;
    virtual bool unregister_message_listener(
        const std::shared_ptr<ProtocolMessageListener> &listener)                            = 0;
    virtual std::future<Reply<PullReplyPayload>> send(const PullMessage &message)            = 0;
    virtual std::future<BasicReply>              send(const PushMessage &message)            = 0;
    virtual bool                                 send(const ByeMessage &message)             = 0;
    virtual std::future<BasicReply>              send(const DeadMessage &message)            = 0;
    virtual std::future<BasicReply>              send(const PingMessage &message)            = 0;
    virtual std::future<BasicReply>              send(const DNLSyncMessage &message)         = 0;
    virtual std::future<BasicReply>              send(const SearchMessage &message)          = 0;
    virtual std::future<BasicReply>              send(const OfferMessage &message)           = 0;
    virtual std::future<BasicReply>              send(const UncacheMessage &message)         = 0;
    virtual std::future<BasicReply>              send(const ConfirmTransferMessage &message) = 0;
    virtual std::future<BasicReply>              send(const RequestProxyMessage &message)    = 0;
    virtual std::future<BasicReply>              send(const InitUploadMessage &message)      = 0;
    virtual std::future<BasicReply>              send(const UploadMessage &message)          = 0;
    virtual std::future<BasicReply>              send(const FetchMessage &message)           = 0;
    virtual std::future<BasicReply>              send(const InitDownloadMessage &message)    = 0;
};
}  // namespace sand::protocol

#endif  // SAND_PROTOCOL_PROTOCOLMESSAGEHANDLER_HPP_
