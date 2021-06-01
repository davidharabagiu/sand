#ifndef SAND_UTILS_IOTHREADPOOL_HPP_
#define SAND_UTILS_IOTHREADPOOL_HPP_

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <queue>
#include <thread>
#include <utility>

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
    CompletionToken add_job(Job &&job, Priority /*priority*/ = default_priority) override;
    void            process_all_jobs() override;

private:
    void ThreadRoutine();

    std::vector<std::thread>                    threads_;
    int                                         idle_thread_count_;
    size_t                                      jobs_to_process_;
    std::queue<std::pair<Job, CompletionToken>> pending_jobs_;
    std::atomic_bool                            running_;
    std::mutex                                  mutex_;
    std::condition_variable                     cv_empty_;
    std::condition_variable                     cv_jobs_left_;
};
}  // namespace sand::utils

#endif  // SAND_UTILS_IOTHREADPOOL_HPP_
