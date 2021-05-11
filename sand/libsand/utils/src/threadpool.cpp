#include "threadpool.hpp"

#include <memory>

namespace sand::utils
{
ThreadPool::ThreadPool(size_t thread_count)
    : jobs_count_ {0}
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

void ThreadPool::AddJob(const Job &job, Priority priority)
{
    auto job_copy = job;
    AddJob(std::move(job_copy), priority);
}

void ThreadPool::AddJob(Job &&job, Priority priority)
{
    {
        std::lock_guard<std::mutex> lock {mutex_};
        jobs_[priority].emplace(std::move(job));
        ++jobs_count_;
    }
    cv_empty_.notify_one();
}

size_t ThreadPool::DefaultThreadCount()
{
    return std::thread::hardware_concurrency();
}

void ThreadPool::ThreadRoutine()
{
    while (running_)
    {
        Job job;

        std::unique_lock<std::mutex> lock {mutex_};
        cv_empty_.wait(lock, [this] { return jobs_count_ != 0 || !running_; });

        if (!running_)
        {
            break;
        }

        auto  it             = jobs_.rbegin();
        auto  max_prio       = it->first;
        auto &max_prio_queue = it->second;
        job                  = std::move(max_prio_queue.front());
        max_prio_queue.pop();
        if (max_prio_queue.empty())
        {
            jobs_.erase(max_prio);
        }

        --jobs_count_;

        lock.unlock();
        job();
    }
}
}  // namespace sand::utils
