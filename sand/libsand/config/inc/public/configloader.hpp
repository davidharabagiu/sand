#ifndef SAND_CONFIG_CONFIGLOADER_HPP_
#define SAND_CONFIG_CONFIGLOADER_HPP_

#include <any>
#include <map>
#include <string>

namespace sand::config
{
class ConfigLoader
{
public:
    virtual ~ConfigLoader() = default;

    [[nodiscard]] virtual std::map<std::string, std::any> load() const = 0;
};
}  // namespace sand::config

#endif  // SAND_CONFIG_CONFIGLOADER_HPP_
