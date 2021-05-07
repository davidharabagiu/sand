#ifndef SAND_CRYPTO_RSACIPHER_HPP_
#define SAND_CRYPTO_RSACIPHER_HPP_

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace sand::crypto
{
class RSACipher
{
public:
    virtual ~RSACipher() = default;

    using Key        = std::string;
    using ByteVector = std::vector<uint8_t>;

    [[nodiscard]] virtual std::pair<Key, Key> generate_key_pair(
        size_t bits, uint_least64_t e) const = 0;
    [[nodiscard]] virtual ByteVector encrypt(
        const Key &public_key, const ByteVector &plain_text) const = 0;
    [[nodiscard]] virtual ByteVector decrypt(
        const Key &private_key, const ByteVector &cipher_text) const = 0;
};
}  // namespace sand::crypto

#endif  // SAND_CRYPTO_RSACIPHER_HPP_
