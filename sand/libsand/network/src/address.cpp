#include "address.hpp"

#include <sstream>

namespace sand::network::conversion
{
IPv4Address to_ipv4_address(const std::string &str)
{
    std::istringstream         ss {str};
    sand::network::IPv4Address result = 0;
    for (int i = 0; i != 4; ++i)
    {
        sand::network::IPv4Address byte;
        ss >> byte;
        ss.get();
        result <<= 8;
        result |= byte;
    }
    return result;
}

std::string to_string(IPv4Address address)
{
    std::ostringstream ss;
    for (int i = 0; i != 4; ++i)
    {
        ss << ((address & 0xff000000) >> 24);
        if (i == 3)
        {
            break;
        }
        ss << '.';
        address <<= 8;
    }
    return ss.str();
}
}  // namespace sand::network::conversion
