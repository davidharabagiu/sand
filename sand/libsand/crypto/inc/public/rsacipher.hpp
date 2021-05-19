#ifndef SAND_CRYPTO_RSACIPHER_HPP_
#define SAND_CRYPTO_RSACIPHER_HPP_

#include <cstdint>
#include <future>
#include <string>
#include <vector>

namespace sand::utils
{
class Executer;
}

namespace sand::crypto
{
class RSACipher
{
public:
    virtual ~RSACipher() = default;

    using Key        = std::string;
    using ByteVector = std::vector<uint8_t>;

    enum ModulusSize : uint_least16_t
    {
        M512  = 512,
        M1024 = 1024,
        M2048 = 2048,
        M4096 = 4096,
        M8192 = 8192
    };

    enum PublicExponent : uint_least32_t
    {
        E3     = 3,
        E17    = 17,
        E31    = 31,
        E37    = 37,
        E65537 = 65537
    };

    [[nodiscard]] virtual std::future<bool>       generate_key_pair(ModulusSize modulus_size,
              PublicExponent public_exponent, Key &public_key, Key &private_key,
              utils::Executer &executer)                                             = 0;
    [[nodiscard]] virtual std::future<ByteVector> encrypt(const Key &public_key,
        const ByteVector &plain_text, utils::Executer &executer, int job_count = 1)  = 0;
    [[nodiscard]] virtual std::future<ByteVector> decrypt(const Key &private_key,
        const ByteVector &cipher_text, utils::Executer &executer, int job_count = 1) = 0;
};
}  // namespace sand::crypto

#endif  // SAND_CRYPTO_RSACIPHER_HPP_
