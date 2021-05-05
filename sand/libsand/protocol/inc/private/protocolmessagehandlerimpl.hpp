#ifndef SAND_PROTOCOL_PROTOCOLMESSAGEHANDLERIMPL_HPP_
#define SAND_PROTOCOL_PROTOCOLMESSAGEHANDLERIMPL_HPP_

#include <memory>

#include "listenergroup.hpp"
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
    utils::ListenerGroup<ProtocolMessageListener> listener_group_;
    std::shared_ptr<network::TCPSender>           tcp_sender_;
    std::shared_ptr<network::TCPServer>           tcp_server_;
    std::shared_ptr<const MessageSerializer>      message_serializer_;
};
}  // namespace sand::protocol

#endif  // SAND_PROTOCOL_PROTOCOLMESSAGEHANDLERIMPL_HPP_
