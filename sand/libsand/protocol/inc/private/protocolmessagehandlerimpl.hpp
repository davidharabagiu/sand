#ifndef SAND_PROTOCOL_PROTOCOLMESSAGEHANDLERIMPL_HPP_
#define SAND_PROTOCOL_PROTOCOLMESSAGEHANDLERIMPL_HPP_

#include "listenergroup.hpp"
#include "protocolmessagehandler.hpp"
#include "protocolmessagelistener.hpp"

namespace sand::protocol
{
class ProtocolMessageHandlerImpl : public ProtocolMessageHandler
{
public:
    bool register_message_listener(
        const std::shared_ptr<ProtocolMessageListener> &listener) override;
    bool unregister_message_listener(
        const std::shared_ptr<ProtocolMessageListener> &listener) override;
    std::future<Reply<PullReplyPayload>> send(const PullMessage &message) override;
    std::future<BasicReply>              send(const PushMessage &message) override;
    bool                                 send(const ByeMessage &message) override;
    std::future<BasicReply>              send(const DeadMessage &message) override;
    std::future<BasicReply>              send(const PingMessage &message) override;
    std::future<BasicReply>              send(const DNLSyncMessage &message) override;
    std::future<BasicReply>              send(const SearchMessage &message) override;
    std::future<BasicReply>              send(const OfferMessage &message) override;
    std::future<BasicReply>              send(const UncacheMessage &message) override;
    std::future<BasicReply>              send(const ConfirmTransferMessage &message) override;
    std::future<BasicReply>              send(const RequestProxyMessage &message) override;
    std::future<BasicReply>              send(const InitUploadMessage &message) override;
    std::future<BasicReply>              send(const UploadMessage &message) override;
    std::future<BasicReply>              send(const FetchMessage &message) override;
    std::future<BasicReply>              send(const InitDownloadMessage &message) override;

private:
    utils::ListenerGroup<ProtocolMessageListener> listener_group_;
};
}  // namespace sand::protocol

#endif  // SAND_PROTOCOL_PROTOCOLMESSAGEHANDLERIMPL_HPP_
