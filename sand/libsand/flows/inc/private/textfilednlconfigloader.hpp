#ifndef SAND_FLOWS_TEXTFILEDNLCONFIGLOADER_HPP_
#define SAND_FLOWS_TEXTFILEDNLCONFIGLOADER_HPP_

#include <string>

#include "dnlconfigloader.hpp"

namespace sand::flows
{
class TextFileDNLConfigLoader : public DNLConfigLoader
{
public:
    explicit TextFileDNLConfigLoader(std::string file_name);
    [[nodiscard]] std::vector<network::IPv4Address> load() override;

private:
    std::string file_name_;
};
}  // namespace sand::flows

#endif  // SAND_FLOWS_TEXTFILEDNLCONFIGLOADER_HPP_
