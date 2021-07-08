#include "config.hpp"

#include "configloader.hpp"

namespace sand::config
{
Config::Config(const ConfigLoader &              config_loader,
    std::unique_ptr<FallbackConfigValueProvider> fallback_value_provider)
    : fallback_value_provider_ {std::move(fallback_value_provider)}
{
    auto loaded_configuration = config_loader.load();
    for (ConfigKey k = ConfigKey::FIRST_KEY; k != ConfigKey::KEY_COUNT;
         k           = ConfigKey::EnumType(k + 1))
    {
        auto it = loaded_configuration.find(k.to_string());
        if (it == loaded_configuration.end())
        {
            continue;
        }
        values_[k] = std::move(it->second);
    }
}
}  // namespace sand::config
