#include "dnlflowlistenerdelegate.hpp"

namespace sand
{
void DNLFlowListenerDelegate::register_as_listener(flows::DNLFlow &flow)
{
    flow.register_listener(shared_from_this());
}

void DNLFlowListenerDelegate::unregister_as_listener(flows::DNLFlow &flow)
{
    flow.unregister_listener(shared_from_this());
}

void DNLFlowListenerDelegate::set_on_state_changed_cb(OnStateChangedCb &&cb)
{
    on_state_changed_cb_ = cb;
}

void DNLFlowListenerDelegate::set_on_node_connected_cb(OnNodeConnectedCb &&cb)
{
    on_node_connected_cb_ = cb;
}

void DNLFlowListenerDelegate::set_on_node_disconnected_cb(OnNodeDisconnectedCb &&cb)
{
    on_node_disconnected_cb_ = cb;
}

void DNLFlowListenerDelegate::on_state_changed(flows::DNLFlow::State new_state)
{
    if (on_state_changed_cb_)
    {
        on_state_changed_cb_(new_state);
    }
}

void DNLFlowListenerDelegate::on_node_connected(network::IPv4Address node_address)
{
    if (on_node_connected_cb_)
    {
        on_node_connected_cb_(node_address);
    }
}

void DNLFlowListenerDelegate::on_node_disconnected(network::IPv4Address node_address)
{
    if (on_node_disconnected_cb_)
    {
        on_node_disconnected_cb_(node_address);
    }
}
}  // namespace sand
