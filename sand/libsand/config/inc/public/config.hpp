#ifndef SAND_CONFIG_CONFIG_HPP_
#define SAND_CONFIG_CONFIG_HPP_

#include <any>
#include <array>
#include <typeinfo>
#include <utility>

#include <glog/logging.h>

#include "configkeys.hpp"

namespace sand::config
{
class ConfigLoader;

class Config
{
public:
    explicit Config(const ConfigLoader &config_loader);

    [[nodiscard]] std::pair<std::string, bool> get_string(ConfigKey key) const
    {
        std::string val;
        bool        ok = get(key, val);
        return std::make_pair(val, ok);
    }

    [[nodiscard]] std::pair<long long, bool> get_integer(ConfigKey key) const
    {
        long long val;
        bool      ok = get(key, val);
        return std::make_pair(val, ok);
    }

    [[nodiscard]] std::pair<double, bool> get_float(ConfigKey key) const
    {
        double val;
        bool   ok = get(key, val);
        return std::make_pair(val, ok);
    }

    [[nodiscard]] std::pair<bool, bool> get_bool(ConfigKey key) const
    {
        bool val;
        bool ok = get(key, val);
        return std::make_pair(val, ok);
    }

private:
    template<typename T>
    bool get(ConfigKey key, T &out) const
    {
        if (key < 0 || key >= ConfigKey::KEY_COUNT)
        {
            LOG(ERROR) << "Invalid key " << key;
            return false;
        }

        const auto &val = values_[key];
        if (!val.has_value())
        {
            LOG(ERROR) << "No config value with key " << key.to_string();
            return false;
        }

        try
        {
            out = std::any_cast<T>(val);
        }
        catch (const std::bad_any_cast &e)
        {
            LOG(ERROR) << "Expected value type (" << typeid(T).name()
                       << ") does not match actual the actual type (" << val.type().name() << ")";
            return false;
        }

        return true;
    }

    std::array<std::any, ConfigKey::KEY_COUNT> values_;
};
}  // namespace sand::config

#endif  // SAND_CONFIG_CONFIG_HPP_
