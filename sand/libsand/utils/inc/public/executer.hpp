#ifndef SAND_UTILS_EXECUTER_HPP_
#define SAND_UTILS_EXECUTER_HPP_

#include <functional>

namespace sand::utils
{
class Executer
{
public:
    using Job      = std::function<void()>;
    using Priority = int;

    virtual ~Executer()                                                       = default;
    virtual void AddJob(const Job &job, Priority priority = default_priority) = 0;
    virtual void AddJob(Job &&job, Priority priority = default_priority)      = 0;

    static constexpr Priority default_priority = 0;
};
}  // namespace sand::utils

#endif  // SAND_UTILS_EXECUTER_HPP_
