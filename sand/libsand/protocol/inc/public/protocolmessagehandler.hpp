#ifndef SAND_PROTOCOL_PROTOCOLMESSAGEHANDLER_HPP_
#define SAND_PROTOCOL_PROTOCOLMESSAGEHANDLER_HPP_

#include <future>
#include <memory>

#include "address.hpp"

namespace sand::protocol
{
// Forward declarations
class ProtocolMessageListener;
struct Message;
struct BasicReply;

class ProtocolMessageHandler
{
public:
    virtual ~ProtocolMessageHandler() = default;
    virtual bool register_message_listener(
        const std::shared_ptr<ProtocolMessageListener> &listener) = 0;
    virtual bool unregister_message_listener(
        const std::shared_ptr<ProtocolMessageListener> &listener) = 0;
    virtual std::future<std::unique_ptr<BasicReply>> send(
        network::IPv4Address to, const Message &message) = 0;
};
}  // namespace sand::protocol

#endif  // SAND_PROTOCOL_PROTOCOLMESSAGEHANDLER_HPP_
