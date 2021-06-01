#include "threadpool.hpp"

#include <memory>

namespace sand::utils
{
ThreadPool::ThreadPool(size_t thread_count)
    : jobs_count_ {0}
    , jobs_to_process_ {0}
    , running_ {true}
{
    threads_.reserve(thread_count);
    for (size_t i = 0; i != thread_count; ++i)
    {
        threads_.emplace_back(&ThreadPool::ThreadRoutine, this);
    }
}

ThreadPool::~ThreadPool()
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

CompletionToken ThreadPool::add_job(Job &&job, Priority priority)
{
    CompletionToken completion_token;

    {
        std::lock_guard<std::mutex> lock {mutex_};
        jobs_[priority].emplace(std::move(job), completion_token);
        ++jobs_count_;
        ++jobs_to_process_;
    }
    cv_empty_.notify_one();

    return completion_token;
}

size_t ThreadPool::DefaultThreadCount()
{
    return std::thread::hardware_concurrency();
}

void ThreadPool::ThreadRoutine()
{
    while (running_)
    {
        std::unique_lock<std::mutex> lock {mutex_};
        cv_empty_.wait(lock, [this] { return jobs_count_ != 0 || !running_; });

        if (!running_)
        {
            break;
        }

        auto  it                     = jobs_.rbegin();
        auto  max_prio               = it->first;
        auto &max_prio_queue         = it->second;
        auto [job, completion_token] = std::move(max_prio_queue.front());
        max_prio_queue.pop();
        if (max_prio_queue.empty())
        {
            jobs_.erase(max_prio);
        }

        --jobs_count_;

        lock.unlock();

        if (!completion_token.is_cancelled())
        {
            job(completion_token);
        }
        completion_token.complete();

        lock.lock();
        if (--jobs_to_process_ == 0)
        {
            lock.unlock();
            cv_jobs_left_.notify_all();
        }
    }
}

void ThreadPool::process_all_jobs()
{
    std::unique_lock lock {mutex_};
    cv_jobs_left_.wait(lock, [this] { return jobs_to_process_ == 0; });
}
}  // namespace sand::utils
