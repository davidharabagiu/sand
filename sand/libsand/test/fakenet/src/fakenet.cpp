#include "fakenet.hpp"

FakeNet::FakeNet() = default;

bool FakeNet::next_node(FakeNet::Address addr)
{
    std::lock_guard lock {mutex_};
    if (addr == dynamic_assignment)
    {
        do
        {
            current_assignment_ = rng_.next<Address>();
        } while (!network_map_.emplace(current_assignment_, Node {}).second);
    }
    else
    {
        bool ok = network_map_.emplace(addr, Node {}).second;
        if (!ok)
        {
            return false;
        }
        current_assignment_ = addr;
    }
    return true;
}

FakeNet::Address FakeNet::set_sender_ptr(FakeNet::SenderPtr sender)
{
    std::lock_guard lock {mutex_};
    network_map_.at(current_assignment_).sender = sender;
    return current_assignment_;
}

FakeNet::Address FakeNet::set_server_ptr(FakeNet::ServerPtr server)
{
    std::lock_guard lock {mutex_};
    network_map_.at(current_assignment_).server = server;
    return current_assignment_;
}

FakeNet::ServerPtr FakeNet::get_server_ptr(FakeNet::Address addr) const
{
    std::lock_guard lock {mutex_};
    if (auto it = network_map_.find(addr); it != network_map_.end())
    {
        return it->second.server;
    }
    return nullptr;
}
