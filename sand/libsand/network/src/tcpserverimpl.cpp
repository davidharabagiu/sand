#include "tcpserverimpl.hpp"

#include <glog/logging.h>

#include "address.hpp"
#include "tcpmessagelistener.hpp"

namespace sand::network
{
TCPServerImpl::TCPServerImpl(boost::asio::io_context &io_ctx, unsigned short port)
    : io_ctx_ {io_ctx}
    , acceptor_ {io_ctx_, {boost::asio::ip::tcp::v4(), port}}
{
    listen();
}

TCPServerImpl::~TCPServerImpl()
{
    acceptor_.cancel();
}

bool TCPServerImpl::register_listener(std::shared_ptr<TCPMessageListener> listener)
{
    return listener_group_.add(listener);
}

bool TCPServerImpl::unregister_listener(std::shared_ptr<TCPMessageListener> listener)
{
    return listener_group_.remove(listener);
}

void TCPServerImpl::listen()
{
    acceptor_.listen();
    accept_loop();
}

void TCPServerImpl::accept_loop()
{
    acceptor_.async_accept([this](const boost::system::error_code &connect_error,
                               boost::asio::ip::tcp::socket        socket) {
        if (connect_error)
        {
            LOG(WARNING) << connect_error.message();
            return;
        }

        IPv4Address from =
            conversion::to_ipv4_address(socket.remote_endpoint().address().to_string());
        auto buffer = std::make_shared<boost::asio::streambuf>();

        boost::asio::async_read(socket, *buffer, boost::asio::transfer_all(),
            [this, buffer, from](
                const boost::system::error_code &read_error, std::size_t bytes_read) {
                if (read_error)
                {
                    LOG(WARNING) << read_error.message();
                    return;
                }
                if (bytes_read == 0)
                {
                    LOG(WARNING) << "No bytes read from peer";
                    return;
                }
                listener_group_.notify(&TCPMessageListener::on_message_received, from,
                    boost::asio::buffer_cast<const uint8_t *>(buffer->data()), buffer->size());
            });

        accept_loop();
    });
}
}  // namespace sand::network
