#ifndef SAND_NETWORK_ADDRESS_HPP_
#define SAND_NETWORK_ADDRESS_HPP_

#include <cstdint>
#include <string>

namespace sand::network
{
using IPv4Address = uint32_t;

namespace conversion
{
IPv4Address to_ipv4_address(const std::string &str);
std::string to_string(IPv4Address address);
}  // namespace conversion

}  // namespace sand::network

#endif  // SAND_NETWORK_ADDRESS_HPP_
