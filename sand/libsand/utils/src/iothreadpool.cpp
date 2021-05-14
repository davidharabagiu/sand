#include "iothreadpool.hpp"

#include <memory>

namespace sand::utils
{
IOThreadPool::IOThreadPool()
    : idle_thread_count_ {0}
    , running_ {true}
{
}

IOThreadPool::~IOThreadPool()
{
    {
        std::lock_guard<std::mutex> lock {mutex_};
        running_ = false;
    }

    cv_empty_.notify_all();
    for (auto &th : threads_)
    {
        th.join();
    }
}

void IOThreadPool::add_job(Job &&job, Executer::Priority /*priority*/)
{
    {
        std::lock_guard<std::mutex> lock {mutex_};
        if (idle_thread_count_ == 0)
        {
            threads_.emplace_back(&IOThreadPool::ThreadRoutine, this);
        }
        pending_jobs_.push(std::move(job));
    }
    cv_empty_.notify_one();
}

void IOThreadPool::ThreadRoutine()
{
    while (running_)
    {
        Job job;

        std::unique_lock<std::mutex> lock {mutex_};
        bool                         is_idle = false;
        if (pending_jobs_.empty())
        {
            ++idle_thread_count_;
            is_idle = true;
        }
        cv_empty_.wait(lock, [this] { return !pending_jobs_.empty() || !running_; });
        if (is_idle)
        {
            --idle_thread_count_;
        }

        if (!running_)
        {
            break;
        }

        job = std::move(pending_jobs_.front());
        pending_jobs_.pop();

        lock.unlock();
        job();
    }
}
}  // namespace sand::utils
