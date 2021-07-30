#ifndef SAND_TEST_FAKENET_FAKENET_HPP_
#define SAND_TEST_FAKENET_FAKENET_HPP_

#include <mutex>
#include <unordered_map>

#include "address.hpp"
#include "random.hpp"

namespace sand::network
{
// Forward declarations
class TCPSenderImpl;
class TCPServerImpl;
}  // namespace sand::network

class FakeNet
{
public:
    using Address   = sand::network::IPv4Address;
    using SenderPtr = sand::network::TCPSenderImpl *;
    using ServerPtr = sand::network::TCPServerImpl *;

    static constexpr Address dynamic_assignment = 0;

    FakeNet();
    bool      next_node(Address addr = dynamic_assignment);
    Address   set_sender_ptr(SenderPtr sender);
    Address   set_server_ptr(ServerPtr server);
    ServerPtr get_server_ptr(Address addr) const;
    void      remove_node(Address addr);

private:
    struct Node
    {
        SenderPtr sender;
        ServerPtr server;
    };

    std::unordered_map<Address, Node> network_map_;
    Address                           current_assignment_ {};
    sand::utils::Random               rng_;
    mutable std::mutex                mutex_;
};

#endif  // SAND_TEST_FAKENET_FAKENET_HPP_
