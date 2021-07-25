#include "aescipherimpl.hpp"

#include <memory>

#include <glog/logging.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "defer.hpp"

namespace sand::crypto
{
bool AESCipherImpl::generate_key_and_iv(sand::crypto::AESCipher::KeySize key_size,
    sand::crypto::AESCipher::ModeOfOperation                             mode_of_operation,
    sand::crypto::AESCipher::ByteVector &key, sand::crypto::AESCipher::ByteVector &iv) const
{
    constexpr int data_len = 1024;
    constexpr int salt_len = 8;
    constexpr int rounds   = 5;

    unsigned char data[data_len];
    unsigned char salt[salt_len];

    if (RAND_bytes(data, data_len) != 1 || RAND_bytes(salt, salt_len) != 1)
    {
        LOG(ERROR) << "RAND_bytes failed";
        return false;
    }

    auto cipher = get_cipher(key_size, mode_of_operation);
    if (cipher == nullptr)
    {
        LOG(ERROR) << "Specified AES mode of operation is not implemented";
        return false;
    }

    key.resize(size_t(key_size));
    iv.resize(size_t(key_size));

    int generated_key_length =
        EVP_BytesToKey(cipher, EVP_sha1(), salt, data, data_len, rounds, key.data(), iv.data());
    if (generated_key_length != int(key_size))
    {
        LOG(ERROR) << "Generated key length (" << generated_key_length
                   << ") is different than the requested length (" << int(key_size) << ")";
        return false;
    }

    return true;
}

std::future<AESCipherImpl::ByteVector> AESCipherImpl::encrypt(ModeOfOperation mode_of_operation,
    const ByteVector &key, const ByteVector &iv, const ByteVector &plain_text,
    utils::Executer &executer)
{
    auto promise = std::make_shared<std::promise<ByteVector>>();
    auto future  = promise->get_future();

    auto cipher = get_cipher(static_cast<KeySize>(key.size()), mode_of_operation);
    if (cipher == nullptr)
    {
        LOG(ERROR) << "Cannot derive AES type from provided key size and mode of operation";
        promise->set_value({});
        return future;
    }

    std::lock_guard lock {mutex_};

    running_jobs_.insert(executer.add_job([this, promise, cipher, key, iv, plain_text](
                                              const utils::CompletionToken &completion_token) {
        constexpr size_t aes_block_size = 16;

        auto ctx = EVP_CIPHER_CTX_new();
        if (ctx == nullptr)
        {
            LOG(ERROR) << "EVP_CIPHER_CTX_new failed";
            promise->set_value({});
            return;
        }
        DEFER(EVP_CIPHER_CTX_free(ctx));

        if (EVP_EncryptInit_ex(ctx, cipher, nullptr, key.data(), iv.data()) != 1)
        {
            LOG(ERROR) << "EVP_EncryptInit_ex failed";
            promise->set_value({});
            return;
        }

        ByteVector cipher_text(plain_text.size() + aes_block_size);

        int encrypt_len;
        if (EVP_EncryptUpdate(
                ctx, &cipher_text[0], &encrypt_len, &plain_text[0], int(plain_text.size())) != 1)
        {
            LOG(ERROR) << "EVP_EncryptUpdate failed";
            promise->set_value({});
            return;
        }

        int final_len;
        if (EVP_EncryptFinal_ex(ctx, &cipher_text[size_t(encrypt_len)], &final_len) != 1)
        {
            LOG(ERROR) << "EVP_EncryptFinal_ex failed";
            promise->set_value({});
            return;
        }

        cipher_text.resize(size_t(encrypt_len + final_len));
        promise->set_value(std::move(cipher_text));

        std::lock_guard lock {mutex_};
        running_jobs_.erase(completion_token);
    }));

    return future;
}

std::future<AESCipherImpl::ByteVector> AESCipherImpl::decrypt(ModeOfOperation mode_of_operation,
    const ByteVector &key, const ByteVector &iv, const ByteVector &cipher_text,
    utils::Executer &executer)
{
    auto promise = std::make_shared<std::promise<ByteVector>>();
    auto future  = promise->get_future();

    auto cipher = get_cipher(static_cast<KeySize>(key.size()), mode_of_operation);
    if (cipher == nullptr)
    {
        LOG(ERROR) << "Cannot derive AES type from provided key size and mode of operation";
        promise->set_value({});
        return future;
    }

    {
        std::lock_guard lock {mutex_};
        running_jobs_.insert(executer.add_job([this, promise, cipher, key, iv, cipher_text](
                                                  const utils::CompletionToken &completion_token) {
            auto ctx = EVP_CIPHER_CTX_new();
            if (ctx == nullptr)
            {
                LOG(ERROR) << "EVP_CIPHER_CTX_new failed";
                promise->set_value({});
                return;
            }
            DEFER(EVP_CIPHER_CTX_free(ctx));

            if (EVP_DecryptInit_ex(ctx, cipher, nullptr, key.data(), iv.data()) != 1)
            {
                LOG(ERROR) << "EVP_DecryptInit_ex failed";
                promise->set_value({});
                return;
            }

            ByteVector plain_text(cipher_text.size());

            int decrypt_len;
            if (EVP_DecryptUpdate(ctx, &plain_text[0], &decrypt_len, &cipher_text[0],
                    int(cipher_text.size())) != 1)
            {
                LOG(ERROR) << "EVP_DecryptUpdate failed";
                promise->set_value({});
                return;
            }

            int final_len;
            if (EVP_DecryptFinal_ex(ctx, &plain_text[size_t(decrypt_len)], &final_len) != 1)
            {
                final_len = 0;
            }

            plain_text.resize(size_t(decrypt_len + final_len));
            promise->set_value(std::move(plain_text));

            std::lock_guard lock {mutex_};
            running_jobs_.erase(completion_token);
        }));
    }

    return future;
}

const EVP_CIPHER *AESCipherImpl::get_cipher(KeySize key_size, ModeOfOperation mode_of_operation)
{
    switch (mode_of_operation)
    {
        case CBC:
        {
            switch (key_size)
            {
                case AES128: return EVP_aes_128_cbc();
                case AES192: return EVP_aes_192_cbc();
                case AES256: return EVP_aes_256_cbc();
                default: return nullptr;
            }
        }
        default: return nullptr;
    }
}

AESCipherImpl::~AESCipherImpl()
{
    decltype(running_jobs_) runnings_jobs_copy;

    {
        std::lock_guard lock {mutex_};
        runnings_jobs_copy = running_jobs_;
    }

    for (const auto &completion_token : runnings_jobs_copy)
    {
        completion_token.cancel();
        completion_token.wait_for_completion();
    }
}

}  // namespace sand::crypto
