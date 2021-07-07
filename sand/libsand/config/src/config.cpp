#include "config.hpp"

#include <memory>

#include "configloader.hpp"

namespace sand::config
{
Config::Config(const ConfigLoader &config_loader)
{
    auto loaded_configuration = config_loader.load();
    for (ConfigKey k = ConfigKey::FIRST_KEY; k != ConfigKey::KEY_COUNT;
         k           = ConfigKey::EnumType(k + 1))
    {
        auto it = loaded_configuration.find(k.to_string());
        if (it == loaded_configuration.end())
        {
            LOG(ERROR) << "Missing config value with key " << k.to_string();
            continue;
        }
        values_[k] = std::move(it->second);
    }
}
}  // namespace sand::config
