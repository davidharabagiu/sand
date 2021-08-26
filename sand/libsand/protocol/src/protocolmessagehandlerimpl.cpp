#include "protocolmessagehandlerimpl.hpp"

#include <algorithm>
#include <utility>

#include <glog/logging.h>

#include "config.hpp"
#include "defer.hpp"
#include "messageserializer.hpp"
#include "protocolmessagelistener.hpp"
#include "tcpsender.hpp"
#include "tcpserver.hpp"
#include "timer.hpp"

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
    std::shared_ptr<utils::Executer> io_executer, const config::Config &cfg)
    : tcp_sender_ {std::move(tcp_sender)}
    , tcp_server_ {std::move(tcp_server)}
    , message_serializer_ {std::move(message_serializer)}
    , io_executer_ {std::move(io_executer)}
    , port_ {static_cast<unsigned short>(cfg.get_integer(config::ConfigKey::PORT))}
    , request_timeout_ {std::max(0LL, cfg.get_integer(config::ConfigKey::REQUEST_TIMEOUT))}
{}

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
    return listener_group_.add(listener);
}

bool ProtocolMessageHandlerImpl::unregister_message_listener(
    const std::shared_ptr<ProtocolMessageListener> &listener)
{
    return listener_group_.remove(listener);
}

std::future<std::unique_ptr<BasicReply>> ProtocolMessageHandlerImpl::send(
    network::IPv4Address to, std::unique_ptr<Message> message)
{
    auto reply_promise = std::make_shared<std::promise<std::unique_ptr<BasicReply>>>();
    std::future<std::unique_ptr<BasicReply>> reply_future = reply_promise->get_future();

    auto message_code = message->message_code;
    auto request_id   = message->request_id;

    {
        std::lock_guard<std::mutex> _lock {mutex_};
        if (pending_replies_.count(message->request_id) != 0)
        {
            LOG(ERROR) << "Request with id " << message->request_id << " already sent";
            return {};  // invalid future
        }

        if (message->message_code != MessageCode::BYE)
        {
            pending_replies_.emplace(message->request_id,
                PendingReply {reply_promise, message->message_code, to,
                    add_timeout(request_timeout_, [this, reply_promise, message_code, request_id] {
                        auto reply         = std::make_unique<BasicReply>(message_code);
                        reply->request_id  = request_id;
                        reply->status_code = StatusCode::TIMEOUT;
                        reply_promise->set_value(std::move(reply));

                        std::lock_guard lock {mutex_};
                        pending_replies_.erase(request_id);
                    })});
        }
    }

    auto bytes       = message->serialize(message_serializer_);
    auto send_future = std::make_shared<std::future<bool>>(
        tcp_sender_->send(to, port_, bytes.data(), bytes.size()));

    add_job(io_executer_, [this, reply_promise, send_future, message_code, request_id](
                              const utils::CompletionToken &completion_token) {
        bool success = send_future->get();
        if (completion_token.is_cancelled())
        {
            return;
        }
        if (message_code == MessageCode::BYE)
        {
            reply_promise->set_value({});
            return;
        }
        if (!success)
        {
            {
                std::lock_guard lock {mutex_};
                auto            it = pending_replies_.find(request_id);
                if (it != pending_replies_.end())
                {
                    it->second.timeout->stop();
                    timeouts_.erase(it->second.timeout);
                    pending_replies_.erase(it);
                }
            }

            auto reply         = std::make_unique<BasicReply>(message_code);
            reply->request_id  = request_id;
            reply->status_code = StatusCode::UNREACHABLE;
            reply_promise->set_value(std::move(reply));
        }
    });

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

utils::CompletionToken ProtocolMessageHandlerImpl::add_job(
    const std::shared_ptr<utils::Executer> &executer, utils::Executer::Job &&job)
{
    std::lock_guard lock {mutex_};
    return *running_jobs_
                .insert(executer->add_job(
                    [this, job = std::move(job)](const utils::CompletionToken &completion_token) {
                        job(completion_token);
                        std::lock_guard lock {mutex_};
                        running_jobs_.erase(completion_token);
                    }))
                .first;
}

std::shared_ptr<utils::Timer> ProtocolMessageHandlerImpl::add_timeout(
    std::chrono::seconds duration, std::function<void()> &&func)
{
    decltype(timeouts_)::iterator it;
    std::tie(it, std::ignore) = timeouts_.emplace(std::make_shared<utils::Timer>(io_executer_));
    (*it)->start(
        duration, [this, timer = std::weak_ptr<utils::Timer>(*it), func = std::move(func)] {
            add_job(io_executer_, [this, timer, func](const auto & /*completion_token*/) {
                func();
                std::lock_guard lock {mutex_};
                timeouts_.erase(timer.lock());
            });
        });
    return *it;
}

ProtocolMessageHandlerImpl::RequestDeserializationResultReceptorImpl::
    RequestDeserializationResultReceptorImpl(
        ProtocolMessageHandlerImpl &parent, network::IPv4Address message_source)
    : parent_ {parent}
    , message_source_ {message_source}
{}

void ProtocolMessageHandlerImpl::RequestDeserializationResultReceptorImpl::deserialized(
    const PullMessage &message)
{
    parent_.listener_group_.notify(PullMessageNotification, message_source_, message);
}

void ProtocolMessageHandlerImpl::RequestDeserializationResultReceptorImpl::deserialized(
    const PushMessage &message)
{
    parent_.listener_group_.notify(PushMessageNotification, message_source_, message);
}

void ProtocolMessageHandlerImpl::RequestDeserializationResultReceptorImpl::deserialized(
    const ByeMessage &message)
{
    parent_.listener_group_.notify(ByeMessageNotification, message_source_, message);
}

void ProtocolMessageHandlerImpl::RequestDeserializationResultReceptorImpl::deserialized(
    const DeadMessage &message)
{
    parent_.listener_group_.notify(DeadMessageNotification, message_source_, message);
}

void ProtocolMessageHandlerImpl::RequestDeserializationResultReceptorImpl::deserialized(
    const PingMessage &message)
{
    parent_.listener_group_.notify(PingMessageNotification, message_source_, message);
}

void ProtocolMessageHandlerImpl::RequestDeserializationResultReceptorImpl::deserialized(
    const DNLSyncMessage &message)
{
    parent_.listener_group_.notify(DNLSyncMessageNotification, message_source_, message);
}

void ProtocolMessageHandlerImpl::RequestDeserializationResultReceptorImpl::deserialized(
    const SearchMessage &message)
{
    parent_.listener_group_.notify(SearchMessageNotification, message_source_, message);
}

void ProtocolMessageHandlerImpl::RequestDeserializationResultReceptorImpl::deserialized(
    const OfferMessage &message)
{
    parent_.listener_group_.notify(OfferMessageNotification, message_source_, message);
}

void ProtocolMessageHandlerImpl::RequestDeserializationResultReceptorImpl::deserialized(
    const UncacheMessage &message)
{
    parent_.listener_group_.notify(UncacheMessageNotification, message_source_, message);
}

void ProtocolMessageHandlerImpl::RequestDeserializationResultReceptorImpl::deserialized(
    const ConfirmTransferMessage &message)
{
    parent_.listener_group_.notify(ConfirmTransferMessageNotification, message_source_, message);
}

void ProtocolMessageHandlerImpl::RequestDeserializationResultReceptorImpl::deserialized(
    const RequestDropPointMessage &message)
{
    parent_.listener_group_.notify(RequestDropPointMessageNotification, message_source_, message);
}

void ProtocolMessageHandlerImpl::RequestDeserializationResultReceptorImpl::deserialized(
    const RequestLiftProxyMessage &message)
{
    parent_.listener_group_.notify(RequestLiftProxyMessageNotification, message_source_, message);
}

void ProtocolMessageHandlerImpl::RequestDeserializationResultReceptorImpl::deserialized(
    const InitUploadMessage &message)
{
    parent_.listener_group_.notify(InitUploadMessageNotification, message_source_, message);
}

void ProtocolMessageHandlerImpl::RequestDeserializationResultReceptorImpl::deserialized(
    const UploadMessage &message)
{
    parent_.listener_group_.notify(UploadMessageNotification, message_source_, message);
}

void ProtocolMessageHandlerImpl::RequestDeserializationResultReceptorImpl::deserialized(
    const FetchMessage &message)
{
    parent_.listener_group_.notify(FetchMessageNotification, message_source_, message);
}

void ProtocolMessageHandlerImpl::RequestDeserializationResultReceptorImpl::deserialized(
    const InitDownloadMessage &message)
{
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
{}

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

    it->second.timeout->stop();
    parent_.timeouts_.erase(it->second.timeout);
    it->second.promise->set_value(std::move(reply));
    parent_.pending_replies_.erase(it);
}
}  // namespace sand::protocol
