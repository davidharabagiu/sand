#ifndef SAND_CONFIG_DNLCONFIGLOADER_HPP_
#define SAND_CONFIG_DNLCONFIGLOADER_HPP_

#include <vector>

#include "address.hpp"

namespace sand::config
{
class DNLConfigLoader
{
public:
    virtual ~DNLConfigLoader() = default;

    [[nodiscard]] virtual std::vector<network::IPv4Address> load() = 0;
};
}  // namespace sand::config

#endif  // SAND_CONFIG_DNLCONFIGLOADER_HPP_
