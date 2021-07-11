#ifndef SAND_API_PEERMANAGERFLOWLISTENERDELEGATE_HPP_
#define SAND_API_PEERMANAGERFLOWLISTENERDELEGATE_HPP_

#include <functional>
#include <memory>

#include "address.hpp"
#include "peermanagerflow.hpp"
#include "peermanagerflowlistener.hpp"

namespace sand
{
class PeerManagerFlowListenerDelegate
    : public flows::PeerManagerFlowListener
    , public std::enable_shared_from_this<PeerManagerFlowListenerDelegate>
{
public:
    using OnStateChangedCb     = std::function<void(flows::PeerManagerFlow::State)>;
    using OnPeerDisconnectedCb = std::function<void(network::IPv4Address)>;

    void register_as_listener(flows::PeerManagerFlow &flow);
    void unregister_as_listener(flows::PeerManagerFlow &flow);
    void set_on_state_changed_cb(OnStateChangedCb &&cb);
    void set_on_peer_disconnected_cb(OnPeerDisconnectedCb &&cb);

public:  // from flows::PeerManagerFlowListener
    void on_state_changed(flows::PeerManagerFlow::State new_state) override;
    void on_peer_disconnected(network::IPv4Address address) override;

private:
    OnStateChangedCb     on_state_changed_cb_;
    OnPeerDisconnectedCb on_peer_disconnected_cb_;
};
}  // namespace sand

#endif  // SAND_API_PEERMANAGERFLOWLISTENERDELEGATE_HPP_
