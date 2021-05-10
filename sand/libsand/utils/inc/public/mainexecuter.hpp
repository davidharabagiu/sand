#ifndef SAND_UTILS_MAINEXECUTER_HPP_
#define SAND_UTILS_MAINEXECUTER_HPP_

#include "executer.hpp"

namespace sand::utils
{
class MainExecuter : public Executer
{
public:
    void AddJob(const Job &job, Priority priority) override;
    void AddJob(Job &&job, Priority priority) override;
};
}  // namespace sand::utils

#endif  // SAND_UTILS_MAINEXECUTER_HPP_
