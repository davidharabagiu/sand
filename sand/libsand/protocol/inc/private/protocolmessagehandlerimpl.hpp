#ifndef SAND_PROTOCOL_PROTOCOLMESSAGEHANDLERIMPL_HPP_
#define SAND_PROTOCOL_PROTOCOLMESSAGEHANDLERIMPL_HPP_

#include <chrono>
#include <map>
#include <memory>
#include <mutex>
#include <set>

#include "executer.hpp"
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

namespace sand::config
{
// Forward declarations
class Config;
}  // namespace sand::config

namespace sand::utils
{
// Forward declarations
class Timer;
}  // namespace sand::utils

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
    ProtocolMessageHandlerImpl(std::shared_ptr<network::TCPSender> tcp_sender,
        std::shared_ptr<network::TCPServer>                        tcp_server,
        std::shared_ptr<const MessageSerializer>                   message_serializer,
        std::shared_ptr<utils::Executer> io_executer, const config::Config &cfg);
    ~ProtocolMessageHandlerImpl() override;

    void initialize();
    void uninitialize();

public:  // From ProtocolMessageHandler
    bool register_message_listener(
        const std::shared_ptr<ProtocolMessageListener> &listener) override;
    bool unregister_message_listener(
        const std::shared_ptr<ProtocolMessageListener> &listener) override;
    std::future<std::unique_ptr<BasicReply>> send(
        network::IPv4Address to, std::unique_ptr<Message> message) override;
    std::future<bool> send_reply(
        network::IPv4Address to, std::unique_ptr<BasicReply> message) override;

public:  // From network::TCPMessageListener
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
        void deserialized(const RequestDropPointMessage &message) override;
        void deserialized(const RequestLiftProxyMessage &message) override;
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

    struct PendingReply
    {
        std::shared_ptr<std::promise<std::unique_ptr<BasicReply>>> promise;
        MessageCode                                                message_code;
        network::IPv4Address                                       from;
        std::shared_ptr<utils::Timer>                              timeout;
    };

    utils::CompletionToken add_job(
        const std::shared_ptr<utils::Executer> &executer, utils::Executer::Job &&job);
    std::shared_ptr<utils::Timer> add_timeout(
        std::chrono::seconds duration, std::function<void()> &&func);

    utils::ListenerGroup<ProtocolMessageListener>  listener_group_;
    const std::shared_ptr<network::TCPSender>      tcp_sender_;
    const std::shared_ptr<network::TCPServer>      tcp_server_;
    const std::shared_ptr<const MessageSerializer> message_serializer_;
    const std::shared_ptr<utils::Executer>         io_executer_;
    std::map<RequestId, PendingReply>              pending_replies_;
    unsigned short                                 port_;
    std::chrono::seconds                           request_timeout_;
    std::set<utils::CompletionToken>               running_jobs_;
    std::set<std::shared_ptr<utils::Timer>>        timeouts_;
    std::mutex                                     mutex_;

    friend class RequestDeserializationResultReceptorImpl;
};
}  // namespace sand::protocol

#endif  // SAND_PROTOCOL_PROTOCOLMESSAGEHANDLERIMPL_HPP_
