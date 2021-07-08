#ifndef SAND_CONFIG_CONFIG_HPP_
#define SAND_CONFIG_CONFIG_HPP_

#include <any>
#include <array>
#include <memory>
#include <typeinfo>

#include <glog/logging.h>

#include "configkeys.hpp"
#include "fallbackconfigvalueprovider.hpp"

namespace sand::config
{
class ConfigLoader;

class Config
{
public:
    explicit Config(const ConfigLoader &             config_loader,
        std::unique_ptr<FallbackConfigValueProvider> fallback_value_provider = nullptr);

    [[nodiscard]] std::string get_string(ConfigKey key) const
    {
        return get<std::string>(key);
    }

    [[nodiscard]] long long get_integer(ConfigKey key) const
    {
        return get<long long>(key);
    }

    [[nodiscard]] double get_float(ConfigKey key) const
    {
        return get<double>(key);
    }

    [[nodiscard]] bool get_bool(ConfigKey key) const
    {
        return get<bool>(key);
    }

private:
    template<typename T>
    [[nodiscard]] T get(ConfigKey key) const
    {
        if (key < 0 || key >= ConfigKey::KEY_COUNT)
        {
            LOG(FATAL) << "Invalid key " << key;
        }

        const auto &val = values_[key];
        if (!val.has_value())
        {
            LOG(ERROR) << "No config value with key " << key.to_string();
            return get_fallback_value<T>(key);
        }

        try
        {
            return std::any_cast<T>(val);
        }
        catch (const std::bad_any_cast &e)
        {
            LOG(ERROR) << "Expected value type (" << typeid(T).name()
                       << ") does not match actual the actual type (" << val.type().name() << ")";
            return get_fallback_value<T>(key);
        }
    }

    template<typename T>
    [[nodiscard]] T get_fallback_value(ConfigKey key) const
    {
        if (!fallback_value_provider_)
        {
            LOG(FATAL) << "Fallback config value provider is missing, cannot continue execution...";
        }

        std::any val = fallback_value_provider_->get(key);
        if (!val.has_value())
        {
            LOG(FATAL) << "No fallback config value with key " << key.to_string();
        }

        try
        {
            return std::any_cast<T>(fallback_value_provider_->get(key));
        }
        catch (const std::bad_any_cast &e)
        {
            LOG(FATAL) << "Expected value type (" << typeid(T).name()
                       << ") does not match actual the actual type of the fallback value ("
                       << val.type().name() << ")";
        }

        return T {};
    }

    std::array<std::any, ConfigKey::KEY_COUNT> values_;
    const std::shared_ptr<FallbackConfigValueProvider>
        fallback_value_provider_;  // make it shared_ptr so a Config object is copyable
};
}  // namespace sand::config

#endif  // SAND_CONFIG_CONFIG_HPP_
