#ifndef SAND_FLOWS_DNLCONFIG_HPP_
#define SAND_FLOWS_DNLCONFIG_HPP_

#include <memory>
#include <vector>

#include "address.hpp"
#include "random.hpp"

namespace sand::flows
{
// Forward declarations
class DNLConfigLoader;

class DNLConfig
{
public:
    explicit DNLConfig(std::unique_ptr<DNLConfigLoader> loader);
    ~DNLConfig();

    void                               reload();
    [[nodiscard]] network::IPv4Address random_pick();
    void                               exclude(network::IPv4Address address);
    [[nodiscard]] bool                 is_empty() const;

private:
    std::vector<network::IPv4Address> pool_;
    std::unique_ptr<DNLConfigLoader>  loader_;
    utils::Random                     rng_;
};
}  // namespace sand::flows

#endif  // SAND_FLOWS_DNLCONFIG_HPP_
