#ifndef SAND_UTILS_MAINEXECUTER_HPP_
#define SAND_UTILS_MAINEXECUTER_HPP_

#include "executer.hpp"

namespace sand::utils
{
class MainExecuter : public Executer
{
public:
    CompletionToken add_job(Job &&job, Priority priority = default_priority) override;
    void            process_all_jobs() override;
};
}  // namespace sand::utils

#endif  // SAND_UTILS_MAINEXECUTER_HPP_
