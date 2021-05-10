#ifndef SAND_CRYPTO_RSACIPHERIMPL_HPP_
#define SAND_CRYPTO_RSACIPHERIMPL_HPP_

#include <map>
#include <mutex>

#include "rsacipher.hpp"

typedef struct bio_st BIO;
typedef struct rsa_st RSA;
typedef int           pem_password_cb(char *, int, int, void *);

namespace sand::crypto
{
class RSACipherImpl : public RSACipher
{
public:
    [[nodiscard]] std::future<bool>       generate_key_pair(ModulusSize modulus_size,
              PublicExponent public_exponent, Key &public_key, Key &private_key,
              utils::Executer &executer) const override;
    [[nodiscard]] std::future<ByteVector> encrypt(const Key &public_key,
        const ByteVector &plain_text, utils::Executer &executer, int job_count) const override;
    [[nodiscard]] std::future<ByteVector> decrypt(const Key &private_key,
        const ByteVector &cipher_text, utils::Executer &executer, int job_count) const override;

private:
    using OpenSSLReadKeyFunction = RSA *(*) (BIO *, RSA **, pem_password_cb *, void *);
    using OpenSSLCryptoFunction  = int (*)(int, const unsigned char *, unsigned char *, RSA *, int);

    [[nodiscard]] static std::future<ByteVector> start_operation(const Key &key,
        const ByteVector &plain_text, utils::Executer &executer, int job_count,
        OpenSSLReadKeyFunction read_key_function, OpenSSLCryptoFunction crypto_function,
        bool subtract_padding);

    struct CipherOperation
    {
        CipherOperation(std::promise<ByteVector> &&a_promise, RSA *a_rsa, BIO *a_key_bio,
            ByteVector a_bytes_to_process, size_t a_key_len, size_t a_block_len, int a_job_count);
        void completion(int job_index, ByteVector &&partial_result);
        void error();

        std::promise<ByteVector> promise;
        RSA *                    rsa;
        BIO *                    key_bio;
        ByteVector               bytes_to_process;
        size_t                   key_len;
        size_t                   block_len;
        int                      pending_jobs;

    private:
        void cleanup() const;

        bool                      error_signaled;
        std::map<int, ByteVector> partial_results;
        std::mutex                mutex;
    };
};
}  // namespace sand::crypto

#endif  // SAND_CRYPTO_RSACIPHERIMPL_HPP_
