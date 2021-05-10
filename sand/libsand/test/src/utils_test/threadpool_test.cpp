#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <future>
#include <mutex>

#include "threadpool.hpp"

using namespace ::sand::utils;
using namespace ::testing;

namespace
{
class ThreadPoolTest : public Test
{
protected:
    void SetUp() override
    {
    }
};
}  // namespace

TEST_F(ThreadPoolTest, SamePriority_PreserveInsertionOrder)
{
    ThreadPool thread_pool {1};

    std::mutex              mut;
    std::condition_variable cv;

    const int        total_jobs = 10;
    int              done_jobs  = 0;
    std::vector<int> execution_order;

    for (int i = 0; i != total_jobs; ++i)
    {
        thread_pool.AddJob(
            [&, job_index = i] {
                {
                    std::lock_guard<std::mutex> lock {mut};
                    ++done_jobs;
                    execution_order.push_back(job_index);
                }
                cv.notify_one();
            },
            ThreadPool::default_priority);
    }

    std::unique_lock<std::mutex> lock {mut};
    bool                         done =
        cv.wait_for(lock, std::chrono::milliseconds {100}, [&] { return total_jobs == done_jobs; });
    bool ordered = std::is_sorted(execution_order.cbegin(), execution_order.cend());

    EXPECT_TRUE(done);
    EXPECT_TRUE(ordered);
}

TEST_F(ThreadPoolTest, SamePriority_MultipleThreads)
{
    ThreadPool thread_pool {8};

    std::mutex              mut;
    std::condition_variable cv;

    const int total_jobs = 10;
    int       done_jobs  = 0;

    for (int i = 0; i != total_jobs; ++i)
    {
        thread_pool.AddJob(
            [&] {
                {
                    std::lock_guard<std::mutex> lock {mut};
                    ++done_jobs;
                }
                cv.notify_one();
            },
            ThreadPool::default_priority);
    }

    std::unique_lock<std::mutex> lock {mut};
    bool                         done =
        cv.wait_for(lock, std::chrono::milliseconds {100}, [&] { return total_jobs == done_jobs; });

    EXPECT_TRUE(done);
}

TEST_F(ThreadPoolTest, DifferentPriorities_PreserveOrder)
{
    ThreadPool thread_pool {1};

    std::mutex              mut;
    std::condition_variable cv;

    const int                       total_jobs = 10;
    int                             done_jobs  = 0;
    std::vector<Executer::Priority> execution_order;

    // Add filler job to keep the thread busy while adding the other jobs
    std::promise<void> promise_keep_busy;
    auto               future_keep_busy = promise_keep_busy.get_future();
    std::promise<void> promise_start_filler_job;
    auto               future_start_filler_job = promise_start_filler_job.get_future();
    thread_pool.AddJob(
        [&] {
            promise_start_filler_job.set_value();
            future_keep_busy.wait();
        },
        0);

    // Wait for filler job to start executing
    future_start_filler_job.wait();

    // Add jobs in reverse priority order
    for (int i = 0; i != total_jobs; ++i)
    {
        Executer::Priority p = i + 1;
        thread_pool.AddJob(
            [&, priority = p] {
                {
                    std::lock_guard<std::mutex> lock {mut};
                    ++done_jobs;
                    execution_order.push_back(priority);
                }
                cv.notify_one();
            },
            p);
    }

    // Let the filler job finish
    promise_keep_busy.set_value();

    std::unique_lock<std::mutex> lock {mut};
    bool                         done =
        cv.wait_for(lock, std::chrono::milliseconds {100}, [&] { return total_jobs == done_jobs; });
    bool ordered = std::is_sorted(
        execution_order.cbegin(), execution_order.cend(), [](auto p1, auto p2) { return p1 > p2; });

    EXPECT_TRUE(done);
    EXPECT_TRUE(ordered);
}

TEST_F(ThreadPoolTest, DifferentPriorities_MultipleThreads)
{
    ThreadPool thread_pool {8};

    std::mutex              mut;
    std::condition_variable cv;

    const int total_jobs = 10;
    int       done_jobs  = 0;

    for (int i = 0; i != total_jobs; ++i)
    {
        Executer::Priority p = i + 1;
        thread_pool.AddJob(
            [&] {
                {
                    std::lock_guard<std::mutex> lock {mut};
                    ++done_jobs;
                }
                cv.notify_one();
            },
            p);
    }

    std::unique_lock<std::mutex> lock {mut};
    bool                         done =
        cv.wait_for(lock, std::chrono::milliseconds {100}, [&] { return total_jobs == done_jobs; });

    EXPECT_TRUE(done);
}
