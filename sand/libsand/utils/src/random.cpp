#include "random.hpp"

namespace sand::utils
{
std::unique_ptr<Random::State> Random::state_;
std::mutex                     Random::state_mutex_;

Random::Random()
{
    std::lock_guard lock {state_mutex_};
    if (!state_)
    {
        state_ = std::make_unique<State>();
    }
}

void Random::reseed()
{
    std::lock_guard lock {state_mutex_};
    state_->prng.seed(state_->trng());
}
}  // namespace sand::utils
