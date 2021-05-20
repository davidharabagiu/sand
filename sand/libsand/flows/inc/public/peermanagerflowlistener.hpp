#ifndef SAND_FLOWS_PEERMANAGERFLOWLISTENER_HPP_
#define SAND_FLOWS_PEERMANAGERFLOWLISTENER_HPP_

#include "peermanagerflow.hpp"

namespace sand::flows
{
class PeerManagerFlowListener
{
public:
    virtual ~PeerManagerFlowListener() = default;

    virtual void on_state_changed(PeerManagerFlow::State new_state) = 0;
};
}  // namespace sand::flows

#endif  // SAND_FLOWS_PEERMANAGERFLOWLISTENER_HPP_
