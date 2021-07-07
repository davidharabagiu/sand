#ifndef SAND_CONFIG_TEXTFILEDNLCONFIGLOADER_HPP_
#define SAND_CONFIG_TEXTFILEDNLCONFIGLOADER_HPP_

#include <string>

#include "dnlconfigloader.hpp"

namespace sand::config
{
class TextFileDNLConfigLoader : public DNLConfigLoader
{
public:
    explicit TextFileDNLConfigLoader(std::string file_name);
    [[nodiscard]] std::vector<network::IPv4Address> load() override;

private:
    std::string file_name_;
};
}  // namespace sand::config

#endif  // SAND_CONFIG_TEXTFILEDNLCONFIGLOADER_HPP_
