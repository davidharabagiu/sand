#ifndef SAND_CONFIG_DNLCONFIG_HPP_
#define SAND_CONFIG_DNLCONFIG_HPP_

#include <memory>
#include <mutex>
#include <vector>

#include "address.hpp"
#include "random.hpp"

namespace sand::config
{
// Forward declarations
class DNLConfigLoader;

class DNLConfig
{
public:
    explicit DNLConfig(std::unique_ptr<DNLConfigLoader> loader);
    ~DNLConfig();

    void                                            reload();
    [[nodiscard]] std::vector<network::IPv4Address> get_all() const;
    [[nodiscard]] network::IPv4Address              random_pick();
    void                                            exclude(network::IPv4Address address);
    [[nodiscard]] bool                              is_empty() const;
    [[nodiscard]] bool                              contains(network::IPv4Address address) const;

private:
    std::vector<network::IPv4Address> pool_;
    std::unique_ptr<DNLConfigLoader>  loader_;
    utils::Random                     rng_;
    mutable std::mutex                mutex_;
};
}  // namespace sand::config

#endif  // SAND_CONFIG_DNLCONFIG_HPP_
