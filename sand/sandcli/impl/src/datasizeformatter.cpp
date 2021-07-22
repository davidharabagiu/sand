#include "datasizeformatter.hpp"

#include <algorithm>
#include <cmath>
#include <iomanip>
#include <sstream>

#include <glog/logging.h>

namespace sandcli
{
namespace
{
const char *byte_unit_str(int unit_magnitude)
{
    switch (unit_magnitude)
    {
        case 0: return "B";
        case 1: return "KiB";
        case 2: return "MiB";
        case 3: return "GiB";
        case 4: return "TiB";
        case 5: return "PiB";
        case 6: return "EiB";
        case 7: return "ZiB";
        case 8: return "YiB";
        default:
        {
            LOG(ERROR) << "Unit magnitude too large, returning null string";
            return nullptr;
        }
    }
}
}  // namespace

std::string DataSizeFormatter::format(
    size_t size, int integral_part_max_digits, int fractional_part_max_digits) const
{
    integral_part_max_digits   = std::max(integral_part_max_digits, 1);
    fractional_part_max_digits = std::max(fractional_part_max_digits, 0);
    int  unit_magnitude        = 0;
    auto dbl_size              = double(size);
    int  integral_part_digits;

    while ((integral_part_digits = int(std::to_string(size_t(std::floor(dbl_size))).size())) >
           integral_part_max_digits)
    {
        dbl_size /= 1024;
        ++unit_magnitude;
    }

    std::ostringstream ss;
    ss << std::setprecision(integral_part_digits + fractional_part_max_digits) << dbl_size << ' '
       << byte_unit_str(unit_magnitude);

    return ss.str();
}
}  // namespace sandcli
