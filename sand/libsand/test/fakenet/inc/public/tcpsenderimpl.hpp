#ifndef SAND_TEST_FAKENET_TCPSENDERIMPL_HPP_
#define SAND_TEST_FAKENET_TCPSENDERIMPL_HPP_

#include <boost/asio.hpp>

#include "tcpsender.hpp"

// Forward declarations
class FakeNet;

namespace sand::network
{
class TCPSenderImpl : public TCPSender
{
public:
    explicit TCPSenderImpl(boost::asio::io_context &io_ctx);

    std::future<bool> send(
        IPv4Address to, unsigned short port, const uint8_t *data, size_t len) override;

private:
    FakeNet &   fake_net_;
    IPv4Address my_address_;
};
}  // namespace sand::network

#endif  // SAND_TEST_FAKENET_TCPSENDERIMPL_HPP_
