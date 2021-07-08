#ifndef SAND_CONFIG_FALLBACKCONFIGVALUEPROVIDER_HPP_
#define SAND_CONFIG_FALLBACKCONFIGVALUEPROVIDER_HPP_

#include <any>

namespace sand::config
{
// Forward declarations
class ConfigKey;

class FallbackConfigValueProvider
{
public:
    virtual ~FallbackConfigValueProvider() = default;

    [[nodiscard]] virtual std::any get(const ConfigKey &key) const = 0;
};
}  // namespace sand::config

#endif  // SAND_CONFIG_FALLBACKCONFIGVALUEPROVIDER_HPP_
