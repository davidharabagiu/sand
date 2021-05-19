#ifndef SAND_UTILS_EXECUTER_HPP_
#define SAND_UTILS_EXECUTER_HPP_

#include <functional>

#include "completiontoken.hpp"

namespace sand::utils
{
class Executer
{
public:
    using Job      = std::function<void(const CompletionToken &)>;
    using Priority = int;

    virtual ~Executer()                                                              = default;
    virtual CompletionToken add_job(Job &&job, Priority priority = default_priority) = 0;

    static constexpr Priority default_priority = 0;
};
}  // namespace sand::utils

#endif  // SAND_UTILS_EXECUTER_HPP_
