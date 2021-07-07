#ifndef SAND_CONFIG_JSONCONFIGLOADER_HPP_
#define SAND_CONFIG_JSONCONFIGLOADER_HPP_

#include <nlohmann/json.hpp>

#include "configloader.hpp"

namespace sand::config
{
class JSONConfigLoader : public ConfigLoader
{
public:
    explicit JSONConfigLoader(std::string config_file_path);
    [[nodiscard]] std::map<std::string, std::any> load() const override;

private:
    void walk_json(const nlohmann::json &json_root, std::map<std::string, std::any> &out) const;

    const std::string config_file_path_;
};
}  // namespace sand::config

#endif  // SAND_CONFIG_JSONCONFIGLOADER_HPP_
