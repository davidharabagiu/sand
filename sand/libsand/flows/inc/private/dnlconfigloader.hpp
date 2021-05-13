#ifndef SAND_FLOWS_DNLCONFIGLOADER_HPP_
#define SAND_FLOWS_DNLCONFIGLOADER_HPP_

#include <vector>

#include "address.hpp"

namespace sand::flows
{
class DNLConfigLoader
{
public:
    virtual ~DNLConfigLoader() = default;

    [[nodiscard]] virtual std::vector<network::IPv4Address> load() = 0;
};
}  // namespace sand::flows

#endif  // SAND_FLOWS_DNLCONFIGLOADER_HPP_
