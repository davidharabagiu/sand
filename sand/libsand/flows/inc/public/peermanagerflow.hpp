#ifndef SAND_FLOWS_PEERMANAGERFLOW_HPP_
#define SAND_FLOWS_PEERMANAGERFLOW_HPP_

#include <memory>

namespace sand::flows
{
// Forward declarations
class PeerManagerFlowListener;

class PeerManagerFlow
{
public:
    enum class State
    {
        IDLE,
        STARTING,
        RUNNING,
        STOPPING,
        ERROR
    };

    virtual ~PeerManagerFlow() = default;

    virtual void                start()                                                 = 0;
    virtual void                stop()                                                  = 0;
    [[nodiscard]] virtual State state() const                                           = 0;
    virtual bool register_listener(std::shared_ptr<PeerManagerFlowListener> listener)   = 0;
    virtual bool unregister_listener(std::shared_ptr<PeerManagerFlowListener> listener) = 0;
};
}  // namespace sand::flows

#endif  // SAND_FLOWS_PEERMANAGERFLOW_HPP_
