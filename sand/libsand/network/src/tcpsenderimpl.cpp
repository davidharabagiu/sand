#include "tcpsenderimpl.hpp"

#include <memory>
#include <string>

#include <boost/asio.hpp>
#include <glog/logging.h>

namespace sand::network
{
TCPSenderImpl::TCPSenderImpl(boost::asio::io_context &io_ctx)
    : io_ctx_ {io_ctx}
    , resolver_ {io_ctx_}
{
}

std::future<bool> TCPSenderImpl::send(
    IPv4Address to, unsigned short port, const uint8_t *data, size_t len)
{
    auto promise = std::make_shared<std::promise<bool>>();
    auto future  = promise->get_future();
    auto socket  = std::make_shared<boost::asio::ip::tcp::socket>(io_ctx_);

    boost::asio::async_connect(*socket,
        resolver_.resolve(conversion::to_string(to), std::to_string(int(port))),
        [promise, socket, data = std::vector<uint8_t>(data, data + len)](
            const boost::system::error_code &ec_connect,
            const boost::asio::ip::tcp::endpoint & /*ep*/) {
            if (ec_connect)
            {
                LOG(INFO) << ec_connect.message();
                promise->set_value(false);
                return;
            }

            boost::asio::async_write(*socket, boost::asio::buffer(data),
                [promise](const boost::system::error_code &ec_write, size_t /*bytes_transferred*/) {
                    if (ec_write)
                    {
                        LOG(INFO) << ec_write.message();
                        promise->set_value(false);
                        return;
                    }
                    promise->set_value(true);
                });
        });

    return future;
}
}  // namespace sand::network
