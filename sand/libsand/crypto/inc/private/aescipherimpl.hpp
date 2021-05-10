#ifndef SAND_CRYPTO_AESCIPHERIMPL_HPP_
#define SAND_CRYPTO_AESCIPHERIMPL_HPP_

#include "aescipher.hpp"

typedef struct evp_cipher_st EVP_CIPHER;

namespace sand::crypto
{
class AESCipherImpl : public AESCipher
{
public:
    bool generate_key_and_iv(KeySize key_size, ModeOfOperation mode_of_operation, ByteVector &key,
        ByteVector &iv) const override;
    [[nodiscard]] std::future<ByteVector> encrypt(ModeOfOperation mode_of_operation,
        const ByteVector &key, const ByteVector &iv, const ByteVector &plain_text,
        utils::Executer &executer) const override;
    [[nodiscard]] std::future<ByteVector> decrypt(ModeOfOperation mode_of_operation,
        const ByteVector &key, const ByteVector &iv, const ByteVector &cipher_text,
        utils::Executer &executer) const override;

private:
    static const EVP_CIPHER *get_cipher(KeySize key_size, ModeOfOperation mode_of_operation);
};
}  // namespace sand::crypto

#endif  // SAND_CRYPTO_AESCIPHERIMPL_HPP_
