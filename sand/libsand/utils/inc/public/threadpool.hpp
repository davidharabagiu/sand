#ifndef SAND_UTILS_THREADPOOL_HPP_
#define SAND_UTILS_THREADPOOL_HPP_

#include <atomic>
#include <condition_variable>
#include <map>
#include <mutex>
#include <queue>
#include <thread>
#include <utility>
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
    CompletionToken add_job(Job &&job, Priority priority = default_priority) override;
    void            process_all_jobs() override;

    static size_t DefaultThreadCount();

private:
    void ThreadRoutine();

    std::vector<std::thread>                                        threads_;
    std::map<Priority, std::queue<std::pair<Job, CompletionToken>>> jobs_;
    size_t                                                          jobs_count_;
    size_t                                                          jobs_to_process_;
    std::mutex                                                      mutex_;
    std::condition_variable                                         cv_empty_;
    std::condition_variable                                         cv_jobs_left_;
    std::atomic_bool                                                running_;
};
}  // namespace sand::utils

#endif  // SAND_UTILS_THREADPOOL_HPP_
