#ifndef SAND_TEST_PROTOCOLTESTUTILS_HPP_
#define SAND_TEST_PROTOCOLTESTUTILS_HPP_

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

#endif  // SAND_TEST_PROTOCOLTESTUTILS_HPP_
