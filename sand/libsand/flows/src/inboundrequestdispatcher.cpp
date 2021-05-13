#include "inboundrequestdispatcher.hpp"

#include "messages.hpp"
#include "protocolmessagehandler.hpp"

namespace sand::flows
{
InboundRequestDispatcher::InboundRequestDispatcher(
    std::shared_ptr<protocol::ProtocolMessageHandler> protocol_message_handler)
    : protocol_message_handler_ {std::move(protocol_message_handler)}
{
}

void InboundRequestDispatcher::initialize()
{
    protocol_message_handler_->register_message_listener(shared_from_this());
}

void InboundRequestDispatcher::uninitialize()
{
    protocol_message_handler_->unregister_message_listener(shared_from_this());
}

void InboundRequestDispatcher::on_message_received(
    network::IPv4Address from, const protocol::PullMessage &message)
{
    dispatch(from, message);
}

void InboundRequestDispatcher::on_message_received(
    network::IPv4Address from, const protocol::PushMessage &message)
{
    dispatch(from, message);
}

void InboundRequestDispatcher::on_message_received(
    network::IPv4Address from, const protocol::ByeMessage &message)
{
    dispatch(from, message);
}

void InboundRequestDispatcher::on_message_received(
    network::IPv4Address from, const protocol::DeadMessage &message)
{
    dispatch(from, message);
}

void InboundRequestDispatcher::on_message_received(
    network::IPv4Address from, const protocol::PingMessage &message)
{
    dispatch(from, message);
}

void InboundRequestDispatcher::on_message_received(
    network::IPv4Address from, const protocol::DNLSyncMessage &message)
{
    dispatch(from, message);
}

void InboundRequestDispatcher::on_message_received(
    network::IPv4Address from, const protocol::SearchMessage &message)
{
    dispatch(from, message);
}

void InboundRequestDispatcher::on_message_received(
    network::IPv4Address from, const protocol::OfferMessage &message)
{
    dispatch(from, message);
}

void InboundRequestDispatcher::on_message_received(
    network::IPv4Address from, const protocol::UncacheMessage &message)
{
    dispatch(from, message);
}

void InboundRequestDispatcher::on_message_received(
    network::IPv4Address from, const protocol::ConfirmTransferMessage &message)
{
    dispatch(from, message);
}

void InboundRequestDispatcher::on_message_received(
    network::IPv4Address from, const protocol::RequestProxyMessage &message)
{
    dispatch(from, message);
}

void InboundRequestDispatcher::on_message_received(
    network::IPv4Address from, const protocol::InitUploadMessage &message)
{
    dispatch(from, message);
}

void InboundRequestDispatcher::on_message_received(
    network::IPv4Address from, const protocol::UploadMessage &message)
{
    dispatch(from, message);
}

void InboundRequestDispatcher::on_message_received(
    network::IPv4Address from, const protocol::FetchMessage &message)
{
    dispatch(from, message);
}

void InboundRequestDispatcher::on_message_received(
    network::IPv4Address from, const protocol::InitDownloadMessage &message)
{
    dispatch(from, message);
}
}  // namespace sand::flows
