#ifndef SAND_CRYPTO_BASE64ENCODERIMPL_HPP_
#define SAND_CRYPTO_BASE64ENCODERIMPL_HPP_

#include "base64encoder.hpp"

namespace sand::crypto
{
class Base64EncoderImpl : public Base64Encoder
{
public:
    std::string       encode(const Byte *data, size_t len) override;
    std::vector<Byte> decode(const std::string &data) override;
};
}  // namespace sand::crypto

#endif  // SAND_CRYPTO_BASE64ENCODERIMPL_HPP_
