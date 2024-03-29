#ifndef SAND_FLOWS_DNLFLOWLISTENER_HPP_
#define SAND_FLOWS_DNLFLOWLISTENER_HPP_

#include "address.hpp"
#include "dnlflow.hpp"

namespace sand::flows
{
class DNLFlowListener
{
public:
    virtual ~DNLFlowListener() = default;

    virtual void on_state_changed(DNLFlow::State new_state)              = 0;
    virtual void on_node_connected(network::IPv4Address node_address)    = 0;
    virtual void on_node_disconnected(network::IPv4Address node_address) = 0;
};
}  // namespace sand::flows

#endif  // SAND_FLOWS_DNLFLOWLISTENER_HPP_
