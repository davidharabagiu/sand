#ifndef SANDCLI_DATASIZEFORMATTER_HPP_
#define SANDCLI_DATASIZEFORMATTER_HPP_

#include <cstddef>
#include <string>

namespace sandcli
{
class DataSizeFormatter
{
public:
    [[nodiscard]] std::string format(
        size_t size, int integral_part_max_digits = 3, int fractional_part_max_digits = 3) const;
};
}  // namespace sandcli

#endif  // SANDCLI_DATASIZEFORMATTER_HPP_
