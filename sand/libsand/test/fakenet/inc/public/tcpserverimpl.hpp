#ifndef SAND_TEST_FAKENET_TCPSERVERIMPL_HPP_
#define SAND_TEST_FAKENET_TCPSERVERIMPL_HPP_

#include <boost/asio.hpp>

#include "address.hpp"
#include "listenergroup.hpp"
#include "tcpmessagelistener.hpp"
#include "tcpserver.hpp"

// Forward declarations
class FakeNet;

namespace sand::network
{
class TCPServerImpl : public TCPServer
{
public:
    TCPServerImpl(boost::asio::io_context &io_ctx, unsigned short port);

    bool register_listener(std::shared_ptr<TCPMessageListener> listener) override;
    bool unregister_listener(std::shared_ptr<TCPMessageListener> listener) override;

    void inject_message(IPv4Address from, const uint8_t *data, size_t len);

private:
    FakeNet &                                fake_net_;
    utils::ListenerGroup<TCPMessageListener> listener_group_;
};
}  // namespace sand::network

#endif  // SAND_TEST_FAKENET_TCPSERVERIMPL_HPP_
