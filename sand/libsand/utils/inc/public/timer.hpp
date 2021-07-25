#ifndef SAND_UTILS_TIMER_HPP_
#define SAND_UTILS_TIMER_HPP_

#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>

#include "completiontoken.hpp"

namespace sand::utils
{
// Forward declarations
class Executer;

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
    bool restart();
    bool stop();

private:
    const std::shared_ptr<Executer> executer_;
    TimePoint                       next_trigger_moment_;
    std::optional<CompletionToken>  completion_token_;
    Period                          period_;
    Callback                        callback_;
    bool                            single_shot_;
    std::mutex                      mutex_;
};
}  // namespace sand::utils

#endif  // SAND_UTILS_TIMER_HPP_
