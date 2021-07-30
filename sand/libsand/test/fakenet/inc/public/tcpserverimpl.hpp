#ifndef SAND_TEST_FAKENET_TCPSERVERIMPL_HPP_
#define SAND_TEST_FAKENET_TCPSERVERIMPL_HPP_

#include "address.hpp"
#include "fakenet.hpp"
#include "listenergroup.hpp"
#include "singleton.hpp"
#include "tcpmessagelistener.hpp"
#include "tcpserver.hpp"
#include "threadpool.hpp"

namespace sand::network
{
class TCPServerImpl : public TCPServer
{
public:
    template<typename... Ts>
    explicit TCPServerImpl(Ts &&...)
        : fake_net_ {Singleton<FakeNet>::get()}
        , my_address_ {fake_net_.set_server_ptr(this)}
        , thread_pool_ {1}
    {}

    ~TCPServerImpl() override;

    bool register_listener(std::shared_ptr<TCPMessageListener> listener) override;
    bool unregister_listener(std::shared_ptr<TCPMessageListener> listener) override;

    void inject_message(IPv4Address from, const uint8_t *data, size_t len);

private:
    FakeNet &                                fake_net_;
    network::IPv4Address                     my_address_;
    utils::ListenerGroup<TCPMessageListener> listener_group_;
    utils::ThreadPool                        thread_pool_;
};
}  // namespace sand::network

#endif  // SAND_TEST_FAKENET_TCPSERVERIMPL_HPP_
