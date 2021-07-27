#include "tcpsenderimpl.hpp"

#include "fakenet.hpp"
#include "singleton.hpp"
#include "tcpserverimpl.hpp"

namespace sand::network
{
TCPSenderImpl::TCPSenderImpl(boost::asio::io_context & /*io_ctx*/)
    : fake_net_ {Singleton<FakeNet>::get()}
    , my_address_ {fake_net_.set_sender_ptr(this)}
{}

std::future<bool> TCPSenderImpl::send(
    IPv4Address to, unsigned short /*port*/, const uint8_t *data, size_t len)
{
    std::promise<bool> promise;
    auto               future = promise.get_future();

    TCPServerImpl *server = fake_net_.get_server_ptr(to);
    if (!server)
    {
        promise.set_value(false);
        return future;
    }

    server->inject_message(my_address_, data, len);
    promise.set_value(true);
    return future;
}
}  // namespace sand::network
