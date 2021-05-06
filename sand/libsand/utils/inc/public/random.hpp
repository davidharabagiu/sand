#ifndef SAND_UTILS_RANDOM_HPP_
#define SAND_UTILS_RANDOM_HPP_

#include <cstdint>
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

private:
    std::random_device trng_;
    std::mt19937_64    prng_;
};
}  // namespace sand::utils

#endif  // SAND_UTILS_RANDOM_HPP_
