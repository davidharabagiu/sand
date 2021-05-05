#ifndef SAND_NETWORK_TCPSENDER_HPP_
#define SAND_NETWORK_TCPSENDER_HPP_

#include <functional>

#include "address.hpp"

namespace sand::network
{
class TCPSender
{
public:
    using ReplyCallback = std::function<void(const uint8_t *data, size_t len)>;

    virtual ~TCPSender() = default;

    virtual bool send(IPv4Address to, const uint8_t *data, size_t len, ReplyCallback callback) = 0;
};
}  // namespace sand::network

#endif  // SAND_NETWORK_TCPSENDER_HPP_
