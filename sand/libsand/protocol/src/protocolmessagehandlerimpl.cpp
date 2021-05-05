#include "protocolmessagehandlerimpl.hpp"

#include <utility>

#include "messages.hpp"
#include "messageserializer.hpp"
#include "protocolmessagelistener.hpp"
#include "tcpsender.hpp"
#include "tcpserver.hpp"

namespace sand::protocol
{
namespace
{
constexpr void (ProtocolMessageListener::*PullMessageNotification)(
    network::IPv4Address, const PullMessage &) = &ProtocolMessageListener::on_message_received;
constexpr void (ProtocolMessageListener::*PushMessageNotification)(
    network::IPv4Address, const PushMessage &) = &ProtocolMessageListener::on_message_received;
constexpr void (ProtocolMessageListener::*ByeMessageNotification)(
    network::IPv4Address, const ByeMessage &) = &ProtocolMessageListener::on_message_received;
constexpr void (ProtocolMessageListener::*DeadMessageNotification)(
    network::IPv4Address, const DeadMessage &) = &ProtocolMessageListener::on_message_received;
constexpr void (ProtocolMessageListener::*PingMessageNotification)(
    network::IPv4Address, const PingMessage &) = &ProtocolMessageListener::on_message_received;
constexpr void (ProtocolMessageListener::*DNLSyncMessageNotification)(
    network::IPv4Address, const DNLSyncMessage &) = &ProtocolMessageListener::on_message_received;
constexpr void (ProtocolMessageListener::*SearchMessageNotification)(
    network::IPv4Address, const SearchMessage &) = &ProtocolMessageListener::on_message_received;
constexpr void (ProtocolMessageListener::*OfferMessageNotification)(
    network::IPv4Address, const OfferMessage &) = &ProtocolMessageListener::on_message_received;
constexpr void (ProtocolMessageListener::*UncacheMessageNotification)(
    network::IPv4Address, const UncacheMessage &) = &ProtocolMessageListener::on_message_received;
constexpr void (ProtocolMessageListener::*ConfirmTransferMessageNotification)(network::IPv4Address,
    const ConfirmTransferMessage &)               = &ProtocolMessageListener::on_message_received;
constexpr void (ProtocolMessageListener::*RequestProxyMessageNotification)(network::IPv4Address,
    const RequestProxyMessage &)                  = &ProtocolMessageListener::on_message_received;
constexpr void (ProtocolMessageListener::*InitUploadMessageNotification)(network::IPv4Address,
    const InitUploadMessage &)                    = &ProtocolMessageListener::on_message_received;
constexpr void (ProtocolMessageListener::*UploadMessageNotification)(
    network::IPv4Address, const UploadMessage &) = &ProtocolMessageListener::on_message_received;
constexpr void (ProtocolMessageListener::*FetchMessageNotification)(
    network::IPv4Address, const FetchMessage &) = &ProtocolMessageListener::on_message_received;
constexpr void (ProtocolMessageListener::*InitDownloadMessageNotification)(network::IPv4Address,
    const InitDownloadMessage &)                = &ProtocolMessageListener::on_message_received;

class RequestDeserializationResultReceptorImpl : public RequestDeserializationResultReceptor
{
public:
    RequestDeserializationResultReceptorImpl(
        utils::ListenerGroup<ProtocolMessageListener> &listener_group,
        network::IPv4Address                           message_source)
        : listener_group_ {listener_group}
        , message_source_ {message_source}
    {
    }

    void deserialized(const PullMessage &message) override
    {
        listener_group_.notify(PullMessageNotification, message_source_, message);
    }

    void deserialized(const PushMessage &message) override
    {
        listener_group_.notify(PushMessageNotification, message_source_, message);
    }

    void deserialized(const ByeMessage &message) override
    {
        listener_group_.notify(ByeMessageNotification, message_source_, message);
    }

    void deserialized(const DeadMessage &message) override
    {
        listener_group_.notify(DeadMessageNotification, message_source_, message);
    }

    void deserialized(const PingMessage &message) override
    {
        listener_group_.notify(PingMessageNotification, message_source_, message);
    }

    void deserialized(const DNLSyncMessage &message) override
    {
        listener_group_.notify(DNLSyncMessageNotification, message_source_, message);
    }

    void deserialized(const SearchMessage &message) override
    {
        listener_group_.notify(SearchMessageNotification, message_source_, message);
    }

    void deserialized(const OfferMessage &message) override
    {
        listener_group_.notify(OfferMessageNotification, message_source_, message);
    }

    void deserialized(const UncacheMessage &message) override
    {
        listener_group_.notify(UncacheMessageNotification, message_source_, message);
    }

    void deserialized(const ConfirmTransferMessage &message) override
    {
        listener_group_.notify(ConfirmTransferMessageNotification, message_source_, message);
    }

    void deserialized(const RequestProxyMessage &message) override
    {
        listener_group_.notify(RequestProxyMessageNotification, message_source_, message);
    }

    void deserialized(const InitUploadMessage &message) override
    {
        listener_group_.notify(InitUploadMessageNotification, message_source_, message);
    }

    void deserialized(const UploadMessage &message) override
    {
        listener_group_.notify(UploadMessageNotification, message_source_, message);
    }

    void deserialized(const FetchMessage &message) override
    {
        listener_group_.notify(FetchMessageNotification, message_source_, message);
    }

    void deserialized(const InitDownloadMessage &message) override
    {
        listener_group_.notify(InitDownloadMessageNotification, message_source_, message);
    }

    void error() override
    {
    }

private:
    utils::ListenerGroup<ProtocolMessageListener> &listener_group_;
    network::IPv4Address                           message_source_;
};
}  // namespace

ProtocolMessageHandlerImpl::ProtocolMessageHandlerImpl(
    std::shared_ptr<network::TCPSender> tcp_sender, std::shared_ptr<network::TCPServer> tcp_server,
    std::shared_ptr<const MessageSerializer> message_serializer)
    : tcp_sender_ {std::move(tcp_sender)}
    , tcp_server_ {std::move(tcp_server)}
    , message_serializer_ {std::move(message_serializer)}
{
}

ProtocolMessageHandlerImpl::~ProtocolMessageHandlerImpl()
{
    tcp_server_->unregister_listener(shared_from_this());
}

void ProtocolMessageHandlerImpl::initialize()
{
    tcp_server_->register_listener(shared_from_this());
}

bool ProtocolMessageHandlerImpl::register_message_listener(
    const std::shared_ptr<ProtocolMessageListener> &listener)
{
    return listener_group_.add(listener);
}

bool ProtocolMessageHandlerImpl::unregister_message_listener(
    const std::shared_ptr<ProtocolMessageListener> &listener)
{
    return listener_group_.remove(listener);
}

std::future<std::unique_ptr<BasicReply>> ProtocolMessageHandlerImpl::send(
    network::IPv4Address to, const Message &message)
{
    auto reply_promise = std::make_shared<std::promise<std::unique_ptr<BasicReply>>>();
    auto reply_future  = reply_promise->get_future();
    auto request_code  = message.request_code;

    auto bytes = message.serialize(message_serializer_);
    tcp_sender_->send(to,
        bytes.data(),
        bytes.size(),
        [this, request_code, reply_promise](const uint8_t *data, size_t len) {
            std::unique_ptr<BasicReply> reply;
            std::vector<uint8_t>        data_vec(data, data + len);
            bool                        success;

            if (request_code == RequestCode::PULL)
            {
                reply = std::make_unique<PullReply>();
                success =
                    message_serializer_->deserialize(data_vec, static_cast<PullReply &>(*reply));
            }
            else
            {
                reply   = std::make_unique<BasicReply>();
                success = message_serializer_->deserialize(data_vec, *reply);
            }

            if (!success)
            {
                reply.reset();
            }
            reply_promise->set_value(std::move(reply));
        });

    return reply_future;
}

void ProtocolMessageHandlerImpl::on_message_received(
    network::IPv4Address from, const uint8_t *data, size_t len)
{
    RequestDeserializationResultReceptorImpl receptor {listener_group_, from};
    message_serializer_->deserialize(std::vector<uint8_t>(data, data + len), receptor);
}
}  // namespace sand::protocol
