#ifndef SAND_UTILS_RANDOM_HPP_
#define SAND_UTILS_RANDOM_HPP_

#include <algorithm>
#include <cstdint>
#include <iterator>
#include <limits>
#include <memory>
#include <mutex>
#include <random>
#include <type_traits>

namespace sand::utils
{
class Random
{
public:
    Random();
    static void reseed();

    template<typename Int = int>
    static auto next(Int max = std::numeric_limits<Int>::max())
        -> std::enable_if_t<std::is_integral_v<Int>, Int>
    {
        return next<Int>(0, max);
    }

    template<typename Int = int>
    static auto next(Int min, Int max) -> std::enable_if_t<std::is_integral_v<Int>, Int>
    {
        std::uniform_int_distribution<Int> d {min, max};
        std::lock_guard                    lock {state_mutex_};
        return d(state_->prng);
    }

    template<typename Iter>
    static auto shuffle(Iter begin, Iter end)
        -> std::enable_if_t<std::is_same_v<typename std::iterator_traits<Iter>::iterator_category,
            std::random_access_iterator_tag>>
    {
        std::lock_guard lock {state_mutex_};
        std::shuffle(begin, end, state_->prng);
    }

private:
    struct State
    {
        State()
            : prng(trng())
        {}

        std::random_device trng;
        std::mt19937_64    prng;
    };

    static std::unique_ptr<State> state_;
    static std::mutex             state_mutex_;
};
}  // namespace sand::utils

#endif  // SAND_UTILS_RANDOM_HPP_
