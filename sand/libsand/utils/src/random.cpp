#include "random.hpp"

namespace sand::utils
{
Random::Random()
    : prng_(trng_())
{
}

void Random::reseed()
{
    prng_.seed(trng_());
}
}  // namespace sand::utils
