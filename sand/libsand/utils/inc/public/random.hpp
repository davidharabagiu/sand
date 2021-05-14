#ifndef SAND_UTILS_RANDOM_HPP_
#define SAND_UTILS_RANDOM_HPP_

#include <algorithm>
#include <cstdint>
#include <iterator>
#include <limits>
#include <random>
#include <type_traits>

namespace sand::utils
{
class Random
{
public:
    Random();
    void reseed();

    template<typename Int = int>
    auto next(Int max = std::numeric_limits<Int>::max())
        -> std::enable_if_t<std::is_integral_v<Int>, Int>
    {
        return next<Int>(0, max);
    }

    template<typename Int = int>
    auto next(Int min, Int max) -> std::enable_if_t<std::is_integral_v<Int>, Int>
    {
        std::uniform_int_distribution<Int> d {min, max};
        return d(prng_);
    }

    template<typename Iter>
    auto shuffle(Iter begin, Iter end)
        -> std::enable_if_t<std::is_same_v<typename std::iterator_traits<Iter>::iterator_category,
            std::random_access_iterator_tag>>
    {
        std::shuffle(begin, end, prng_);
    }

private:
    std::random_device trng_;
    std::mt19937_64    prng_;
};
}  // namespace sand::utils

#endif  // SAND_UTILS_RANDOM_HPP_
