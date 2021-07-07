#include "jsonconfigloader.hpp"

#include <fstream>
#include <memory>

#include <glog/logging.h>

namespace sand::config
{
JSONConfigLoader::JSONConfigLoader(std::string config_file_path)
    : config_file_path_ {std::move(config_file_path)}
{}

std::map<std::string, std::any> JSONConfigLoader::load() const
{
    std::map<std::string, std::any> values;
    nlohmann::json                  json_root;

    {
        std::ifstream fs {config_file_path_};
        if (!fs.good())
        {
            LOG(ERROR) << "Cannot open " << config_file_path_
                       << " for reading, configuration loading failed.";
            return values;
        }
        fs >> json_root;
    }

    walk_json(json_root, values);

    return values;
}

void JSONConfigLoader::walk_json(
    const nlohmann::json &json_root, std::map<std::string, std::any> &out) const
{
    for (const auto &[k, v] : json_root.items())
    {
        if (v.is_string())
        {
            out.emplace(k, v.get<std::string>());
        }
        else if (v.is_number_integer())
        {
            out.emplace(k, v.get<long long>());
        }
        else if (v.is_number_float())
        {
            out.emplace(k, v.get<double>());
        }
        else if (v.is_boolean())
        {
            out.emplace(k, v.get<bool>());
        }
        else if (v.is_object())
        {
            walk_json(v, out);
        }
        else
        {
            LOG(WARNING) << "Invalid field type for configuration JSON (key = " << k << ")";
        }
    }
}
}  // namespace sand::config
