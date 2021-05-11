#ifndef SAND_UTILS_IOTHREADPOOL_HPP_
#define SAND_UTILS_IOTHREADPOOL_HPP_

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <queue>
#include <thread>

#include "executer.hpp"

namespace sand::utils
{
class IOThreadPool : public Executer
{
public:
    IOThreadPool();
    IOThreadPool(const IOThreadPool &) = delete;
    IOThreadPool &operator=(const IOThreadPool &) = delete;

    ~IOThreadPool() override;
    void AddJob(const Job &job, Priority /*priority*/ = Executer::default_priority) override;
    void AddJob(Job &&job, Priority /*priority*/ = Executer::default_priority) override;

private:
    void ThreadRoutine();

    std::vector<std::thread> threads_;
    int                      idle_thread_count_;
    std::queue<Job>          pending_jobs_;
    std::atomic_bool         running_;
    std::mutex               mutex_;
    std::condition_variable  cv_empty_;
};
}  // namespace sand::utils

#endif  // SAND_UTILS_IOTHREADPOOL_HPP_
