#include <gtest/gtest.h>

#include <chrono>

#include "iothreadpool.hpp"

using namespace ::sand::utils;
using namespace ::testing;

namespace
{
class IOThreadPoolTest : public Test
{
protected:
    void SetUp() override
    {
    }

    void RunTest(int total_jobs)
    {
        IOThreadPool thread_pool;

        std::mutex              mut;
        std::condition_variable cv;

        int                       done_jobs = 0;
        std::chrono::milliseconds job_duration {100};
        std::chrono::milliseconds timeout(job_duration * 11 / 10);

        for (int i = 0; i != total_jobs; ++i)
        {
            thread_pool.AddJob([&] {
                std::this_thread::sleep_for(job_duration);
                {
                    std::lock_guard<std::mutex> lock {mut};
                    ++done_jobs;
                }
                cv.notify_one();
            });
        }

        std::unique_lock<std::mutex> lock {mut};
        bool done = cv.wait_for(lock, timeout, [&] { return total_jobs == done_jobs; });

        EXPECT_TRUE(done);
    }
};
}  // namespace

TEST_F(IOThreadPoolTest, FewJobs)
{
    RunTest(3);
}

TEST_F(IOThreadPoolTest, ManyJobs)
{
    RunTest(100);
}
