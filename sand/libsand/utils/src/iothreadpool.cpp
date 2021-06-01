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

CompletionToken IOThreadPool::add_job(Job &&job, Executer::Priority /*priority*/)
{
    CompletionToken completion_token;

    {
        std::lock_guard<std::mutex> lock {mutex_};
        if (idle_thread_count_ == 0)
        {
            threads_.emplace_back(&IOThreadPool::ThreadRoutine, this);
        }
        pending_jobs_.emplace(std::move(job), completion_token);
    }
    cv_empty_.notify_one();

    return completion_token;
}

void IOThreadPool::ThreadRoutine()
{
    while (running_)
    {
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

        auto [job, completion_token] = std::move(pending_jobs_.front());
        pending_jobs_.pop();

        if (pending_jobs_.empty())
        {
            cv_not_empty_.notify_all();
        }

        lock.unlock();

        if (!completion_token.is_cancelled())
        {
            job(completion_token);
        }

        completion_token.complete();
    }
}

void IOThreadPool::process_all_jobs()
{
    std::unique_lock lock {mutex_};
    cv_not_empty_.wait(lock, [this] { return pending_jobs_.empty(); });
}
}  // namespace sand::utils
