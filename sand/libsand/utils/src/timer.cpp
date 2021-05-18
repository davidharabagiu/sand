#include "timer.hpp"

#include <thread>

#include <glog/logging.h>

namespace sand::utils
{
Timer::Timer(std::shared_ptr<Executer> executer)
    : executer_ {std::move(executer)}
    , running_ {false}
{
}

Timer::~Timer()
{
    if (running_)
    {
        stop();
    }
}

bool Timer::start(Period period, Callback &&callback, bool single_shot)
{
    if (running_)
    {
        LOG(WARNING) << "Timer already running";
        return false;
    }

    next_trigger_moment_      = Clock::now() + period;
    running_                  = true;
    auto job_finished_promise = std::make_shared<std::promise<void>>();
    job_finished_             = job_finished_promise->get_future();

    executer_->add_job(
        [this, period, single_shot, job_finished_promise = std::move(job_finished_promise),
            callback = std::move(callback)] {
            for (;;)
            {
                std::this_thread::sleep_until(next_trigger_moment_);
                next_trigger_moment_ = Clock::now() + period;
                if (!running_)
                {
                    break;
                }
                callback();
                if (single_shot)
                {
                    running_ = false;
                    break;
                }
            }
            job_finished_promise->set_value();
        });

    return true;
}

bool Timer::stop()
{
    if (!running_)
    {
        LOG(WARNING) << "Timer not running";
        return false;
    }
    running_ = false;
    job_finished_.wait();
    return true;
}
}  // namespace sand::utils
