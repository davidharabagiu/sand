#ifndef SAND_CRYPTO_SHA3HASHERIMPL_HPP_
#define SAND_CRYPTO_SHA3HASHERIMPL_HPP_

#include <glog/logging.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "sha3hasher.hpp"

namespace sand::crypto
{
class SHA3HasherImpl : public SHA3Hasher
{
public:
    std::vector<Byte> hash(SHA3_224_t, const Byte *data, size_t len) override;
    std::vector<Byte> hash(SHA3_256_t, const Byte *data, size_t len) override;
    std::vector<Byte> hash(SHA3_384_t, const Byte *data, size_t len) override;
    std::vector<Byte> hash(SHA3_512_t, const Byte *data, size_t len) override;
    std::vector<Byte> hash(SHA3_224_t, InputStream &is) override;
    std::vector<Byte> hash(SHA3_256_t, InputStream &is) override;
    std::vector<Byte> hash(SHA3_384_t, InputStream &is) override;
    std::vector<Byte> hash(SHA3_512_t, InputStream &is) override;

private:
    template<typename InputIt>
    static std::vector<Byte> hash(const EVP_MD *algorithm, size_t digest_length, InputIt data_begin,
        InputIt data_end, size_t buffer_size = DEFAULT_BUFFER_SIZE)
    {
        std::vector<Byte> buffer(buffer_size);

        auto digest = static_cast<Byte *>(OPENSSL_malloc(digest_length));
        if (!digest)
        {
            LOG(FATAL) << "OPENSSL_malloc failed";
        }

        auto ctx = EVP_MD_CTX_new();
        if (!ctx)
        {
            LOG(FATAL) << "EVP_MD_CTX_new failed";
        }

        if (!EVP_DigestInit_ex(ctx, algorithm, nullptr))
        {
            LOG(FATAL) << "EVP_DigestInit_ex failed";
        }

        for (auto it = data_begin; it != data_end;)
        {
            size_t cnt = 0;
            while (cnt != buffer_size)
            {
                buffer[cnt++] = Byte(*it++);
                if (it == data_end)
                {
                    break;
                }
            }

            if (!EVP_DigestUpdate(ctx, buffer.data(), cnt))
            {
                LOG(FATAL) << "EVP_DigestUpdate failed";
            }
        }

        if (!EVP_DigestFinal_ex(ctx, digest, nullptr))
        {
            LOG(FATAL) << "EVP_DigestFinal_ex failed";
        }

        EVP_MD_CTX_destroy(ctx);

        std::vector<Byte> out(digest, digest + digest_length);
        OPENSSL_free(digest);

        return out;
    }

    static constexpr size_t DEFAULT_BUFFER_SIZE = 32 * 1024;  // 32 KiB
};
}  // namespace sand::crypto

#endif  // SAND_CRYPTO_SHA3HASHERIMPL_HPP_
