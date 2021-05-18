#ifndef SAND_UTILS_TIMER_HPP_
#define SAND_UTILS_TIMER_HPP_

#include <atomic>
#include <chrono>
#include <functional>
#include <future>
#include <memory>

#include "executer.hpp"

namespace sand::utils
{
class Timer
{
public:
    using Period    = std::chrono::milliseconds;
    using Clock     = std::chrono::steady_clock;
    using TimePoint = std::chrono::time_point<Clock>;
    using Callback  = std::function<void()>;

    explicit Timer(std::shared_ptr<Executer> executer);
    ~Timer();
    bool start(Period period, Callback &&callback, bool single_shot = false);
    bool stop();

private:
    const std::shared_ptr<Executer> executer_;
    std::atomic_bool                running_;
    TimePoint                       next_trigger_moment_;
    std::future<void>               job_finished_;
};
}  // namespace sand::utils

#endif  // SAND_UTILS_TIMER_HPP_