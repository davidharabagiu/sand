#ifndef SAND_NETWORK_TCPSENDER_HPP_
#define SAND_NETWORK_TCPSENDER_HPP_

#include <future>

#include "address.hpp"

namespace sand::network
{
class TCPSender
{
public:
    virtual ~TCPSender() = default;

    virtual std::future<bool> send(IPv4Address to, int port, const uint8_t *data, size_t len) = 0;
};
}  // namespace sand::network

#endif  // SAND_NETWORK_TCPSENDER_HPP_
