#ifndef SAND_FLOWS_PEERMANAGERFLOW_HPP_
#define SAND_FLOWS_PEERMANAGERFLOW_HPP_

namespace sand::flows
{
class PeerManagerFlow
{
public:
    virtual ~PeerManagerFlow() = default;

    virtual void start() = 0;
    virtual void stop()  = 0;
};
}  // namespace sand::flows

#endif  // SAND_FLOWS_PEERMANAGERFLOW_HPP_
