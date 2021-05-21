#ifndef SAND_TEST_TESTUTILS_HPP_
#define SAND_TEST_TESTUTILS_HPP_

#include <gmock/gmock.h>

#include <cstddef>
#include <functional>
#include <future>
#include <memory>
#include <type_traits>
#include <utility>

#include "address.hpp"
#include "messages.hpp"
#include "random.hpp"

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

bool wait_for(const std::function<bool()> &predicate, unsigned timeout_ms = 0);
sand::network::IPv4Address random_ip_address(sand::utils::Random &rng);
auto                       make_basic_reply_generator(bool ok)
    -> std::function<std::future<std::unique_ptr<sand::protocol::BasicReply>>(
        sand::network::IPv4Address, std::unique_ptr<sand::protocol::Message>)>;
}  // namespace testutils

MATCHER_P(SmartPointerCompare, rhs, "Compares a smart pointer to a raw pointer")
{
    return arg.get() == rhs;
}

#endif  // SAND_TEST_TESTUTILS_HPP_
