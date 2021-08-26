#include "tcpserverimpl.hpp"

#include <chrono>
#include <thread>
#include <vector>

namespace sand::network
{
namespace
{
constexpr long network_time_ms {10};
}  // namespace

TCPServerImpl::~TCPServerImpl()
{
    fake_net_.remove_node(my_address_);
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
    /*
     * Offload to another thread to allow further processing in the node before a reply will be
     * received.
     */
    thread_pool_.add_job(
        [this, from, msg = std::vector<uint8_t>(data, data + len)](const utils::CompletionToken &) {
            std::this_thread::sleep_for(std::chrono::milliseconds {network_time_ms});
            listener_group_.notify(
                &TCPMessageListener::on_message_received, from, msg.data(), msg.size());
        });
}
}  // namespace sand::network
