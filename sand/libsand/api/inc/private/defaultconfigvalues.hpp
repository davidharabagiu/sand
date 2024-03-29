#ifndef SAND_API_DEFAULTCONFIGVALUES_HPP_
#define SAND_API_DEFAULTCONFIGVALUES_HPP_

#include <string>

#include "configkeys.hpp"
#include "fallbackconfigvalueprovider.hpp"

namespace sand
{
class DefaultConfigValues : public config::FallbackConfigValueProvider
{
public:
    DefaultConfigValues();
    [[nodiscard]] std::any get(const config::ConfigKey &key) const override;

private:
    const std::any default_values_[config::ConfigKey::KEY_COUNT];
};
}  // namespace sand

#endif  // SAND_API_DEFAULTCONFIGVALUES_HPP_
