#ifndef SAND_CRYPTO_BASE64ENCODER_HPP_
#define SAND_CRYPTO_BASE64ENCODER_HPP_

#include <cstdint>
#include <string>
#include <vector>

namespace sand::crypto
{
class Base64Encoder
{
public:
    using Byte = uint8_t;

    virtual ~Base64Encoder() = default;

    virtual std::string       encode(const Byte *data, size_t len) = 0;
    virtual std::vector<Byte> decode(const std::string &data)      = 0;
};
}  // namespace sand::crypto

#endif  // SAND_CRYPTO_BASE64ENCODER_HPP_
