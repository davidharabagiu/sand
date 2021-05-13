#ifndef SAND_TEST_TESTUTILS_HPP_
#define SAND_TEST_TESTUTILS_HPP_

#include <gmock/gmock.h>

#include <cstddef>
#include <cstdlib>
#include <string>
#include <type_traits>
#include <utility>

#include "address.hpp"

namespace testutils
{
template<typename OutputIt, typename Int = std::decay_t<decltype(*std::declval<OutputIt>())>>
inline auto random_values(OutputIt dst, size_t count) -> std::enable_if_t<std::is_integral_v<Int>>
{
    while (count--)
    {
        *dst++ = Int(std::rand());
    }
}
}  // namespace testutils

MATCHER_P(SmartPointerCompare, rhs, "Compares a smart pointer to a raw pointer")
{
    return arg.get() == rhs;
}

#endif  // SAND_TEST_TESTUTILS_HPP_
