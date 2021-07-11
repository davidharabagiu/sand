#include "peermanagerflowlistenerdelegate.hpp"

#include "peermanagerflow.hpp"

namespace sand
{
void PeerManagerFlowListenerDelegate::register_as_listener(flows::PeerManagerFlow &flow)
{
    flow.register_listener(shared_from_this());
}

void PeerManagerFlowListenerDelegate::unregister_as_listener(flows::PeerManagerFlow &flow)
{
    flow.unregister_listener(shared_from_this());
}

void PeerManagerFlowListenerDelegate::set_on_state_changed_cb(OnStateChangedCb &&cb)
{
    on_state_changed_cb_ = std::move(cb);
}

void PeerManagerFlowListenerDelegate::set_on_peer_disconnected_cb(
    PeerManagerFlowListenerDelegate::OnPeerDisconnectedCb &&cb)
{
    on_peer_disconnected_cb_ = std::move(cb);
}

void PeerManagerFlowListenerDelegate::on_state_changed(flows::PeerManagerFlow::State new_state)
{
    if (on_state_changed_cb_)
    {
        on_state_changed_cb_(new_state);
    }
}

void PeerManagerFlowListenerDelegate::on_peer_disconnected(network::IPv4Address address)
{
    if (on_peer_disconnected_cb_)
    {
        on_peer_disconnected_cb_(address);
    }
}
}  // namespace sand
