#ifndef SAND_API_DNLFLOWLISTENERDELEGATE_HPP_
#define SAND_API_DNLFLOWLISTENERDELEGATE_HPP_

#include <functional>
#include <memory>

#include "dnlflow.hpp"
#include "dnlflowlistener.hpp"

namespace sand
{
class DNLFlowListenerDelegate
    : public flows::DNLFlowListener
    , public std::enable_shared_from_this<DNLFlowListenerDelegate>
{
public:
    using OnStateChangedCb     = std::function<void(flows::DNLFlow::State)>;
    using OnNodeConnectedCb    = std::function<void(network::IPv4Address)>;
    using OnNodeDisconnectedCb = std::function<void(network::IPv4Address)>;

    void register_as_listener(flows::DNLFlow &flow);
    void unregister_as_listener(flows::DNLFlow &flow);
    void set_on_state_changed_cb(OnStateChangedCb &&cb);
    void set_on_node_connected_cb(OnNodeConnectedCb &&cb);
    void set_on_node_disconnected_cb(OnNodeDisconnectedCb &&cb);

public:  // from flows::DNLFlowListener
    void on_state_changed(flows::DNLFlow::State new_state) override;
    void on_node_connected(network::IPv4Address node_address) override;
    void on_node_disconnected(network::IPv4Address node_address) override;

private:
    OnStateChangedCb     on_state_changed_cb_;
    OnNodeConnectedCb    on_node_connected_cb_;
    OnNodeDisconnectedCb on_node_disconnected_cb_;
};
}  // namespace sand

#endif  // SAND_API_DNLFLOWLISTENERDELEGATE_HPP_
