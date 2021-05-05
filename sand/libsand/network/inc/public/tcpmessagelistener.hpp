#ifndef SAND_NETWORK_TCPMESSAGELISTENER_HPP_
#define SAND_NETWORK_TCPMESSAGELISTENER_HPP_

#include <cstddef>
#include <cstdint>

#include "address.hpp"

namespace sand::network
{
class TCPMessageListener
{
public:
    virtual ~TCPMessageListener() = default;

    virtual void on_message_received(IPv4Address from, const uint8_t *data, size_t len) = 0;
};
}  // namespace sand::network

#endif  // SAND_NETWORK_TCPMESSAGELISTENER_HPP_
