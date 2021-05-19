#ifndef SAND_CRYPTO_AESCIPHER_HPP_
#define SAND_CRYPTO_AESCIPHER_HPP_

#include <cstdint>
#include <future>
#include <vector>

#include "executer.hpp"

namespace sand::crypto
{
class AESCipher
{
public:
    using ByteVector = std::vector<uint8_t>;

    enum KeySize
    {
        AES128 = 16,
        AES192 = 24,
        AES256 = 32
    };

    enum ModeOfOperation
    {
        CBC
    };

    virtual ~AESCipher() = default;

    virtual bool generate_key_and_iv(KeySize key_size, ModeOfOperation mode_of_operation,
        ByteVector &key, ByteVector &iv) const = 0;

    [[nodiscard]] virtual std::future<ByteVector> encrypt(ModeOfOperation mode_of_operation,
        const ByteVector &key, const ByteVector &iv, const ByteVector &plain_text,
        utils::Executer &executer) = 0;
    [[nodiscard]] virtual std::future<ByteVector> decrypt(ModeOfOperation mode_of_operation,
        const ByteVector &key, const ByteVector &iv, const ByteVector &cipher_text,
        utils::Executer &executer) = 0;
};
}  // namespace sand::crypto

#endif  // SAND_CRYPTO_AESCIPHER_HPP_
