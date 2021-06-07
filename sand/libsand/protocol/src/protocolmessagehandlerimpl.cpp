#include "protocolmessagehandlerimpl.hpp"

#include <utility>

#include <glog/logging.h>

#include "defer.hpp"
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
constexpr void (ProtocolMessageListener::*RequestDropPointMessageNotification)(network::IPv4Address,
    const RequestDropPointMessage &)              = &ProtocolMessageListener::on_message_received;
constexpr void (ProtocolMessageListener::*RequestLiftProxyMessageNotification)(network::IPv4Address,
    const RequestLiftProxyMessage &)              = &ProtocolMessageListener::on_message_received;
constexpr void (ProtocolMessageListener::*InitUploadMessageNotification)(network::IPv4Address,
    const InitUploadMessage &)                    = &ProtocolMessageListener::on_message_received;
constexpr void (ProtocolMessageListener::*UploadMessageNotification)(
    network::IPv4Address, const UploadMessage &) = &ProtocolMessageListener::on_message_received;
constexpr void (ProtocolMessageListener::*FetchMessageNotification)(
    network::IPv4Address, const FetchMessage &) = &ProtocolMessageListener::on_message_received;
constexpr void (ProtocolMessageListener::*InitDownloadMessageNotification)(network::IPv4Address,
    const InitDownloadMessage &)                = &ProtocolMessageListener::on_message_received;
}  // namespace

ProtocolMessageHandlerImpl::ProtocolMessageHandlerImpl(
    std::shared_ptr<network::TCPSender> tcp_sender, std::shared_ptr<network::TCPServer> tcp_server,
    std::shared_ptr<const MessageSerializer> message_serializer,
    std::shared_ptr<utils::Executer> io_executer, unsigned short port)
    : tcp_sender_ {std::move(tcp_sender)}
    , tcp_server_ {std::move(tcp_server)}
    , message_serializer_ {std::move(message_serializer)}
    , io_executer_ {std::move(io_executer)}
    , port_ {port}
{
}

ProtocolMessageHandlerImpl::~ProtocolMessageHandlerImpl()
{
    decltype(running_jobs_) runnings_jobs_copy;

    {
        std::lock_guard lock {mutex_};
        runnings_jobs_copy = running_jobs_;
    }

    for (const auto &completion_token : runnings_jobs_copy)
    {
        completion_token.cancel();
        completion_token.wait_for_completion();
    }
}

void ProtocolMessageHandlerImpl::initialize()
{
    tcp_server_->register_listener(shared_from_this());
}

void ProtocolMessageHandlerImpl::uninitialize()
{
    tcp_server_->unregister_listener(shared_from_this());
}

bool ProtocolMessageHandlerImpl::register_message_listener(
    const std::shared_ptr<ProtocolMessageListener> &listener)
{
    std::lock_guard<std::mutex> _lock {mutex_};
    return listener_group_.add(listener);
}

bool ProtocolMessageHandlerImpl::unregister_message_listener(
    const std::shared_ptr<ProtocolMessageListener> &listener)
{
    std::lock_guard<std::mutex> _lock {mutex_};
    return listener_group_.remove(listener);
}

std::future<std::unique_ptr<BasicReply>> ProtocolMessageHandlerImpl::send(
    network::IPv4Address to, std::unique_ptr<Message> message)
{
    auto reply_promise = std::make_shared<std::promise<std::unique_ptr<BasicReply>>>();
    std::future<std::unique_ptr<BasicReply>> reply_future = reply_promise->get_future();

    {
        std::lock_guard<std::mutex> _lock {mutex_};
        if (outgoing_request_ids_.count(message->request_id) != 0 ||
            pending_replies_.count(message->request_id) != 0)
        {
            LOG(ERROR) << "Request with id " << message->request_id << " already sent";
            return {};  // invalid future
        }
        outgoing_request_ids_.insert(message->request_id);
    }

    auto bytes              = message->serialize(message_serializer_);
    auto send_result_future = std::make_shared<std::future<bool>>(
        tcp_sender_->send(to, port_, bytes.data(), bytes.size()));

    std::shared_ptr<Message> shared_message {std::move(message)};

    {
        std::lock_guard lock {mutex_};
        running_jobs_.insert(io_executer_->add_job(
            [this, send_result_future, message = shared_message, reply_promise, to](
                const utils::CompletionToken &completion_token) {
                DEFER({
                    std::lock_guard lock {mutex_};
                    running_jobs_.erase(completion_token);
                });

                bool success = send_result_future->get();

                if (completion_token.is_cancelled())
                {
                    reply_promise->set_value(nullptr);
                    return;
                }

                std::lock_guard<std::mutex> _lock {mutex_};
                outgoing_request_ids_.erase(message->request_id);

                if (message->message_code == MessageCode::BYE)
                {
                    reply_promise->set_value(nullptr);
                }
                else if (success)
                {
                    pending_replies_.emplace(message->request_id,
                        PendingReply {reply_promise, message->message_code, to});
                }
                else
                {
                    auto reply         = std::make_unique<BasicReply>(message->message_code);
                    reply->request_id  = message->request_id;
                    reply->status_code = StatusCode::UNREACHABLE;
                    reply_promise->set_value(std::move(reply));
                }
            }));
    }

    return reply_future;
}

std::future<bool> ProtocolMessageHandlerImpl::send_reply(
    network::IPv4Address to, std::unique_ptr<BasicReply> message)
{
    auto bytes = message->serialize(message_serializer_);
    return tcp_sender_->send(to, port_, bytes.data(), bytes.size());
}

void ProtocolMessageHandlerImpl::on_message_received(
    network::IPv4Address from, const uint8_t *data, size_t len)
{
    RequestDeserializationResultReceptorImpl receptor {*this, from};
    message_serializer_->deserialize(std::vector<uint8_t>(data, data + len), receptor);
}

ProtocolMessageHandlerImpl::RequestDeserializationResultReceptorImpl::
    RequestDeserializationResultReceptorImpl(
        ProtocolMessageHandlerImpl &parent, network::IPv4Address message_source)
    : parent_ {parent}
    , message_source_ {message_source}
{
}

void ProtocolMessageHandlerImpl::RequestDeserializationResultReceptorImpl::deserialized(
    const PullMessage &message)
{
    std::lock_guard<std::mutex> _lock {parent_.mutex_};
    parent_.listener_group_.notify(PullMessageNotification, message_source_, message);
}

void ProtocolMessageHandlerImpl::RequestDeserializationResultReceptorImpl::deserialized(
    const PushMessage &message)
{
    std::lock_guard<std::mutex> _lock {parent_.mutex_};
    parent_.listener_group_.notify(PushMessageNotification, message_source_, message);
}

void ProtocolMessageHandlerImpl::RequestDeserializationResultReceptorImpl::deserialized(
    const ByeMessage &message)
{
    std::lock_guard<std::mutex> _lock {parent_.mutex_};
    parent_.listener_group_.notify(ByeMessageNotification, message_source_, message);
}

void ProtocolMessageHandlerImpl::RequestDeserializationResultReceptorImpl::deserialized(
    const DeadMessage &message)
{
    std::lock_guard<std::mutex> _lock {parent_.mutex_};
    parent_.listener_group_.notify(DeadMessageNotification, message_source_, message);
}

void ProtocolMessageHandlerImpl::RequestDeserializationResultReceptorImpl::deserialized(
    const PingMessage &message)
{
    std::lock_guard<std::mutex> _lock {parent_.mutex_};
    parent_.listener_group_.notify(PingMessageNotification, message_source_, message);
}

void ProtocolMessageHandlerImpl::RequestDeserializationResultReceptorImpl::deserialized(
    const DNLSyncMessage &message)
{
    std::lock_guard<std::mutex> _lock {parent_.mutex_};
    parent_.listener_group_.notify(DNLSyncMessageNotification, message_source_, message);
}

void ProtocolMessageHandlerImpl::RequestDeserializationResultReceptorImpl::deserialized(
    const SearchMessage &message)
{
    std::lock_guard<std::mutex> _lock {parent_.mutex_};
    parent_.listener_group_.notify(SearchMessageNotification, message_source_, message);
}

void ProtocolMessageHandlerImpl::RequestDeserializationResultReceptorImpl::deserialized(
    const OfferMessage &message)
{
    std::lock_guard<std::mutex> _lock {parent_.mutex_};
    parent_.listener_group_.notify(OfferMessageNotification, message_source_, message);
}

void ProtocolMessageHandlerImpl::RequestDeserializationResultReceptorImpl::deserialized(
    const UncacheMessage &message)
{
    std::lock_guard<std::mutex> _lock {parent_.mutex_};
    parent_.listener_group_.notify(UncacheMessageNotification, message_source_, message);
}

void ProtocolMessageHandlerImpl::RequestDeserializationResultReceptorImpl::deserialized(
    const ConfirmTransferMessage &message)
{
    std::lock_guard<std::mutex> _lock {parent_.mutex_};
    parent_.listener_group_.notify(ConfirmTransferMessageNotification, message_source_, message);
}

void ProtocolMessageHandlerImpl::RequestDeserializationResultReceptorImpl::deserialized(
    const RequestDropPointMessage &message)
{
    std::lock_guard<std::mutex> _lock {parent_.mutex_};
    parent_.listener_group_.notify(RequestDropPointMessageNotification, message_source_, message);
}

void ProtocolMessageHandlerImpl::RequestDeserializationResultReceptorImpl::deserialized(
    const RequestLiftProxyMessage &message)
{
    std::lock_guard<std::mutex> _lock {parent_.mutex_};
    parent_.listener_group_.notify(RequestLiftProxyMessageNotification, message_source_, message);
}

void ProtocolMessageHandlerImpl::RequestDeserializationResultReceptorImpl::deserialized(
    const InitUploadMessage &message)
{
    std::lock_guard<std::mutex> _lock {parent_.mutex_};
    parent_.listener_group_.notify(InitUploadMessageNotification, message_source_, message);
}

void ProtocolMessageHandlerImpl::RequestDeserializationResultReceptorImpl::deserialized(
    const UploadMessage &message)
{
    std::lock_guard<std::mutex> _lock {parent_.mutex_};
    parent_.listener_group_.notify(UploadMessageNotification, message_source_, message);
}

void ProtocolMessageHandlerImpl::RequestDeserializationResultReceptorImpl::deserialized(
    const FetchMessage &message)
{
    std::lock_guard<std::mutex> _lock {parent_.mutex_};
    parent_.listener_group_.notify(FetchMessageNotification, message_source_, message);
}

void ProtocolMessageHandlerImpl::RequestDeserializationResultReceptorImpl::deserialized(
    const InitDownloadMessage &message)
{
    std::lock_guard<std::mutex> _lock {parent_.mutex_};
    parent_.listener_group_.notify(InitDownloadMessageNotification, message_source_, message);
}

void ProtocolMessageHandlerImpl::RequestDeserializationResultReceptorImpl::deserialized(
    const BasicReply &message)
{
    process_reply(std::make_unique<BasicReply>(message));
}

void ProtocolMessageHandlerImpl::RequestDeserializationResultReceptorImpl::deserialized(
    const PullReply &message)
{
    process_reply(std::make_unique<PullReply>(message));
}

void ProtocolMessageHandlerImpl::RequestDeserializationResultReceptorImpl::error()
{
}

void ProtocolMessageHandlerImpl::RequestDeserializationResultReceptorImpl::process_reply(
    std::unique_ptr<BasicReply> reply)
{
    std::lock_guard<std::mutex> _lock {parent_.mutex_};

    auto it = parent_.pending_replies_.find(reply->request_id);
    if (it == parent_.pending_replies_.end())
    {
        LOG(WARNING) << "Stray reply received; Request id = " << reply->request_id;
        return;
    }
    if (it->second.from != message_source_)
    {
        LOG(WARNING) << "Reply source address (" << network::conversion::to_string(message_source_)
                     << ") does not match the corresponding message destination address ("
                     << network::conversion::to_string(it->second.from) << ")";
        return;
    }
    if (it->second.message_code != reply->request_message_code)
    {
        LOG(WARNING) << "Reply request_message_code (" << int(reply->request_message_code)
                     << ") does not match the corresponding message message_code ("
                     << int(it->second.message_code) << ")";
        return;
    }
    it->second.promise->set_value(std::move(reply));
    parent_.pending_replies_.erase(it);
}
}  // namespace sand::protocol
