#ifndef SAND_NETWORK_TCPSERVERIMPL_HPP_
#define SAND_NETWORK_TCPSERVERIMPL_HPP_

#include <boost/asio.hpp>

#include "listenergroup.hpp"
#include "tcpserver.hpp"

namespace sand::network
{
class TCPServerImpl : public TCPServer
{
public:
    TCPServerImpl(boost::asio::io_context &io_ctx, unsigned short port);
    ~TCPServerImpl() override;

    bool register_listener(std::shared_ptr<TCPMessageListener> listener) override;
    bool unregister_listener(std::shared_ptr<TCPMessageListener> listener) override;

private:
    void listen();
    void accept_loop();

    boost::asio::io_context &                io_ctx_;
    boost::asio::ip::tcp::acceptor           acceptor_;
    utils::ListenerGroup<TCPMessageListener> listener_group_;
};
}  // namespace sand::network

#endif  // SAND_NETWORK_TCPSERVERIMPL_HPP_
