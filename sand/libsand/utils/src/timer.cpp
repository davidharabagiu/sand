#include "timer.hpp"

#include <thread>

#include <glog/logging.h>

#include "executer.hpp"

namespace sand::utils
{
Timer::Timer(std::shared_ptr<Executer> executer)
    : executer_ {std::move(executer)}
    , period_ {}
    , callback_ {}
    , single_shot_ {}
{}

Timer::~Timer()
{
    if (completion_token_)
    {
        stop();
    }
}

bool Timer::start(Period period, Callback &&callback, bool single_shot)
{
    std::lock_guard lock {mutex_};

    if (completion_token_)
    {
        LOG(WARNING) << "Timer already running";
        return false;
    }

    next_trigger_moment_ = Clock::now() + period;
    period_              = period;
    callback_            = std::move(callback);
    single_shot_         = single_shot;

    completion_token_ = executer_->add_job([this](const CompletionToken &completion_token) {
        for (;;)
        {
            TimePoint next_trigger_moment;
            {
                std::lock_guard lock {mutex_};
                next_trigger_moment = next_trigger_moment_;
            }

            std::this_thread::sleep_until(next_trigger_moment);

            std::lock_guard lock {mutex_};
            if (completion_token.is_cancelled())
            {
                break;
            }
            next_trigger_moment_ = Clock::now() + period_;
            callback_();
            if (single_shot_)
            {
                completion_token_.reset();
                break;
            }
        }
    });

    return true;
}

bool Timer::restart()
{
    if (!stop())
    {
        return false;
    }

    return start(period_, std::move(callback_), single_shot_);
}

bool Timer::stop()
{
    std::lock_guard lock {mutex_};

    if (!completion_token_)
    {
        LOG(WARNING) << "Timer not running";
        return false;
    }

    completion_token_->cancel();
    completion_token_.reset();

    return true;
}
}  // namespace sand::utils
