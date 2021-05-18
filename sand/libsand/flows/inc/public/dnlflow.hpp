#ifndef SAND_FLOWS_DNLFLOW_HPP_
#define SAND_FLOWS_DNLFLOW_HPP_

#include <memory>

namespace sand::flows
{
// Forward declarations
class DNLFlowListener;

class DNLFlow
{
public:
    virtual ~DNLFlow() = default;

    virtual bool register_listener(std::shared_ptr<DNLFlowListener> listener)   = 0;
    virtual bool unregister_listener(std::shared_ptr<DNLFlowListener> listener) = 0;
};
}  // namespace sand::flows

#endif  // SAND_FLOWS_DNLFLOW_HPP_
