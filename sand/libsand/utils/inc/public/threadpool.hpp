#ifndef SAND_UTILS_THREADPOOL_HPP_
#define SAND_UTILS_THREADPOOL_HPP_

#include <atomic>
#include <condition_variable>
#include <map>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

#include "executer.hpp"

namespace sand::utils
{
class ThreadPool : public Executer
{
public:
    explicit ThreadPool(size_t thread_count = DefaultThreadCount());
    ThreadPool(const ThreadPool &) = delete;
    ThreadPool &operator=(const ThreadPool &) = delete;

    ~ThreadPool() override;
    void AddJob(const Job &job, Priority priority) override;
    void AddJob(Job &&job, Priority priority) override;

    static size_t DefaultThreadCount();

private:
    void ThreadRoutine();

    std::vector<std::thread>            threads_;
    std::map<Priority, std::queue<Job>> jobs_;
    size_t                              jobs_count_;
    std::mutex                          mutex_;
    std::condition_variable             cv_empty_;
    std::atomic_bool                    running_;
};
}  // namespace sand::utils

#endif  // SAND_UTILS_THREADPOOL_HPP_
