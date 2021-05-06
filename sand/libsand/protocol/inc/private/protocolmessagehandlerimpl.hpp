#ifndef SAND_PROTOCOL_PROTOCOLMESSAGEHANDLERIMPL_HPP_
#define SAND_PROTOCOL_PROTOCOLMESSAGEHANDLERIMPL_HPP_

#include <map>
#include <memory>

#include "listenergroup.hpp"
#include "messagedeserializationresultreceptor.hpp"
#include "messages.hpp"
#include "protocolmessagehandler.hpp"
#include "tcpmessagelistener.hpp"

namespace sand::network
{
// Forward declarations
class TCPSender;
class TCPServer;
}  // namespace sand::network

namespace sand::protocol
{
// Forward declarations
class MessageSerializer;

class ProtocolMessageHandlerImpl
    : public ProtocolMessageHandler
    , public network::TCPMessageListener
    , public std::enable_shared_from_this<ProtocolMessageHandlerImpl>
{
public:
    struct PendingReply
    {
        std::promise<std::unique_ptr<BasicReply>> promise;
        MessageCode                               message_code;
    };

    ProtocolMessageHandlerImpl(std::shared_ptr<network::TCPSender> tcp_sender,
        std::shared_ptr<network::TCPServer>                        tcp_server,
        std::shared_ptr<const MessageSerializer>                   message_serializer);
    ~ProtocolMessageHandlerImpl() override;

    void initialize();

    bool register_message_listener(
        const std::shared_ptr<ProtocolMessageListener> &listener) override;
    bool unregister_message_listener(
        const std::shared_ptr<ProtocolMessageListener> &listener) override;
    std::future<std::unique_ptr<BasicReply>> send(
        network::IPv4Address to, const Message &message) override;

    void on_message_received(network::IPv4Address from, const uint8_t *data, size_t len) override;

private:
    class RequestDeserializationResultReceptorImpl : public MessageDeserializationResultReceptor
    {
    public:
        RequestDeserializationResultReceptorImpl(
            ProtocolMessageHandlerImpl &parent, network::IPv4Address message_source);
        void deserialized(const PullMessage &message) override;
        void deserialized(const PushMessage &message) override;
        void deserialized(const ByeMessage &message) override;
        void deserialized(const DeadMessage &message) override;
        void deserialized(const PingMessage &message) override;
        void deserialized(const DNLSyncMessage &message) override;
        void deserialized(const SearchMessage &message) override;
        void deserialized(const OfferMessage &message) override;
        void deserialized(const UncacheMessage &message) override;
        void deserialized(const ConfirmTransferMessage &message) override;
        void deserialized(const RequestProxyMessage &message) override;
        void deserialized(const InitUploadMessage &message) override;
        void deserialized(const UploadMessage &message) override;
        void deserialized(const FetchMessage &message) override;
        void deserialized(const InitDownloadMessage &message) override;
        void deserialized(const BasicReply &message) override;
        void deserialized(const PullReply &message) override;
        void error() override;

    private:
        void process_reply(std::unique_ptr<BasicReply> reply);

        ProtocolMessageHandlerImpl &parent_;
        network::IPv4Address        message_source_;
    };

    utils::ListenerGroup<ProtocolMessageListener> listener_group_;
    std::shared_ptr<network::TCPSender>           tcp_sender_;
    std::shared_ptr<network::TCPServer>           tcp_server_;
    std::shared_ptr<const MessageSerializer>      message_serializer_;
    std::map<RequestId, PendingReply>             pending_replies_;

    friend class RequestDeserializationResultReceptorImpl;
};
}  // namespace sand::protocol

#endif  // SAND_PROTOCOL_PROTOCOLMESSAGEHANDLERIMPL_HPP_
