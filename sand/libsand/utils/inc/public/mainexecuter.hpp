#ifndef SAND_UTILS_MAINEXECUTER_HPP_
#define SAND_UTILS_MAINEXECUTER_HPP_

#include "executer.hpp"

namespace sand::utils
{
class MainExecuter : public Executer
{
public:
    void add_job(Job &&job, Priority priority = default_priority) override;
};
}  // namespace sand::utils

#endif  // SAND_UTILS_MAINEXECUTER_HPP_
