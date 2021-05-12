#ifndef SAND_NETWORK_TCPSENDERIMPL_HPP_
#define SAND_NETWORK_TCPSENDERIMPL_HPP_

#include <boost/asio.hpp>

#include "tcpsender.hpp"

namespace sand::network
{
class TCPSenderImpl : public TCPSender
{
public:
    TCPSenderImpl(boost::asio::io_context &io_ctx);
    std::future<bool> send(IPv4Address to, int port, const uint8_t *data, size_t len) override;

private:
    boost::asio::io_context &      io_ctx_;
    boost::asio::ip::tcp::resolver resolver_;
};
}  // namespace sand::network

#endif  // SAND_NETWORK_TCPSENDERIMPL_HPP_
