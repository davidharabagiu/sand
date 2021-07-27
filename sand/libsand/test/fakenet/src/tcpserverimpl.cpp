#include "tcpserverimpl.hpp"

#include "fakenet.hpp"
#include "singleton.hpp"

namespace sand::network
{
TCPServerImpl::TCPServerImpl(boost::asio::io_context & /*io_ctx*/, unsigned short /*port*/)
    : fake_net_ {Singleton<FakeNet>::get()}
{
    fake_net_.set_server_ptr(this);
}

bool TCPServerImpl::register_listener(std::shared_ptr<TCPMessageListener> listener)
{
    return listener_group_.add(listener);
}

bool TCPServerImpl::unregister_listener(std::shared_ptr<TCPMessageListener> listener)
{
    return listener_group_.remove(listener);
}

void TCPServerImpl::inject_message(sand::network::IPv4Address from, const uint8_t *data, size_t len)
{
    listener_group_.notify(&TCPMessageListener::on_message_received, from, data, len);
}
}  // namespace sand::network
