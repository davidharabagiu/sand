#include "textfilednlconfigloader.hpp"

#include <fstream>
#include <utility>

namespace sand::config
{
TextFileDNLConfigLoader::TextFileDNLConfigLoader(std::string file_name)
    : file_name_ {std::move(file_name)}
{}

std::vector<network::IPv4Address> TextFileDNLConfigLoader::load()
{
    std::vector<network::IPv4Address> dnl_list;

    std::ifstream fs {file_name_};
    std::string   line;
    while (std::getline(fs, line))
    {
        dnl_list.push_back(network::conversion::to_ipv4_address(line));
    }

    return dnl_list;
}
}  // namespace sand::config
