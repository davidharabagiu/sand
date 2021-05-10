#include "rsacipherimpl.hpp"

#include <algorithm>
#include <memory>
#include <numeric>
#include <utility>

#include <glog/logging.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include "defer.hpp"
#include "executer.hpp"

namespace sand::crypto
{
std::future<bool> RSACipherImpl::generate_key_pair(ModulusSize modulus_size,
    PublicExponent public_exponent, Key &public_key, Key &private_key,
    utils::Executer &executer) const
{
    auto promise = std::make_shared<std::promise<bool>>();

    executer.AddJob([promise, modulus_size, public_exponent, &public_key, &private_key] {
        bool ret = false;
        DEFER(promise->set_value(ret));

        BIGNUM *e = BN_new();
        if (e == nullptr)
        {
            LOG(ERROR) << "BN_new failed";
            ret = false;
            return;
        }
        DEFER(BN_free(e));

        if (BN_set_word(e, static_cast<BN_ULONG>(public_exponent)) != 1)
        {
            LOG(ERROR) << "BN_set_word failed";
            ret = false;
            return;
        }

        RSA *r = RSA_new();
        if (r == nullptr)
        {
            LOG(ERROR) << "RSA_new failed";
            ret = false;
            return;
        }
        DEFER(RSA_free(r));

        if (RSA_generate_key_ex(r, int(modulus_size), e, nullptr) != 1)
        {
            LOG(ERROR) << "RSA_generate_key_ex failed";
            ret = false;
            return;
        }

        BIO *pub = BIO_new(BIO_s_mem());
        if (pub == nullptr)
        {
            LOG(ERROR) << "BIO_new failed";
            ret = false;
            return;
        }
        DEFER(BIO_vfree(pub));

        BIO *pri = BIO_new(BIO_s_mem());
        if (pri == nullptr)
        {
            LOG(ERROR) << "BIO_new failed";
            ret = false;
            return;
        }
        DEFER(BIO_vfree(pri));

        if (PEM_write_bio_RSAPublicKey(pub, r) != 1)
        {
            LOG(ERROR) << "PEM_write_bio_RSAPublicKey failed";
            ret = false;
            return;
        }
        if (PEM_write_bio_RSAPrivateKey(pri, r, nullptr, nullptr, 0, nullptr, nullptr) != 1)
        {
            LOG(ERROR) << "PEM_write_bio_RSAPrivateKey failed";
            ret = false;
            return;
        }

        int pub_len = BIO_pending(pub);
        int pri_len = BIO_pending(pri);

        public_key.resize(size_t(pub_len));
        private_key.resize(size_t(pri_len));

        if (BIO_read(pub, public_key.data(), pub_len) != pub_len)
        {
            LOG(ERROR) << "BIO_read failed";
            ret = false;
            return;
        }
        if (BIO_read(pri, private_key.data(), pri_len) != pri_len)
        {
            LOG(ERROR) << "BIO_read failed";
            ret = false;
            return;
        }

        ret = true;
    });

    return promise->get_future();
}

std::future<RSACipher::ByteVector> RSACipherImpl::encrypt(const Key &public_key,
    const ByteVector &plain_text, utils::Executer &executer, int job_count) const
{
    return start_operation(public_key, plain_text, executer, job_count, PEM_read_bio_RSAPublicKey,
        RSA_public_encrypt, true);
}

std::future<RSACipher::ByteVector> RSACipherImpl::decrypt(const Key &private_key,
    const ByteVector &cipher_text, utils::Executer &executer, int job_count) const
{
    return start_operation(private_key, cipher_text, executer, job_count,
        PEM_read_bio_RSAPrivateKey, RSA_private_decrypt, false);
}

std::future<RSACipher::ByteVector> RSACipherImpl::start_operation(const Key &key,
    const ByteVector &plain_text, utils::Executer &executer, int job_count,
    OpenSSLReadKeyFunction read_key_function, OpenSSLCryptoFunction crypto_function,
    bool subtract_padding)
{
    if (job_count < 1)
    {
        LOG(WARNING) << "Invalid number of jobs specified (" << job_count << "); defaulting to 1";
        job_count = 1;
    }

    std::promise<ByteVector> promise;
    auto                     future = promise.get_future();

    BIO *kb = BIO_new_mem_buf(key.c_str(), -1);
    if (kb == nullptr)
    {
        LOG(ERROR) << "BIO_new_mem_buf failed";
        promise.set_value({});
        return future;
    }

    RSA *r = RSA_new();
    if (r == nullptr)
    {
        LOG(ERROR) << "RSA_new failed";
        promise.set_value({});
        BIO_vfree(kb);
        return future;
    }
    r = read_key_function(kb, &r, nullptr, nullptr);
    if (r == nullptr)
    {
        LOG(ERROR) << "read_key_function failed";
        promise.set_value({});
        BIO_vfree(kb);
        return future;
    }

    auto   key_len        = size_t(RSA_size(r));
    size_t block_len      = key_len - (subtract_padding ? RSA_PKCS1_PADDING_SIZE : 0);
    size_t block_count    = plain_text.size() / block_len + (plain_text.size() % block_len != 0);
    size_t blocks_per_job = block_count / size_t(job_count);

    if (blocks_per_job == 0)
    {
        LOG(WARNING) << "Unneccessary number of jobs specified for the given data to process. "
                        "Defaulting to 1.";
        job_count      = 1;
        blocks_per_job = block_count;
    }

    auto operation = std::make_shared<CipherOperation>(
        std::move(promise), r, kb, plain_text, key_len, block_len, job_count);

    size_t first_block = 0;
    size_t last_block;
    for (int i = 0; i != job_count; ++i)
    {
        last_block = (i == job_count - 1) ? (block_count - 1) : (first_block + blocks_per_job - 1);

        executer.AddJob([operation, crypto_function, first_block, last_block, job_index = i] {
            ByteVector partial_result;

            for (size_t current_block = first_block; current_block <= last_block; ++current_block)
            {
                size_t block_index = current_block * operation->block_len;
                size_t in_byte_cnt = std::min(
                    operation->block_len, operation->bytes_to_process.size() - block_index);
                ByteVector bytes(operation->key_len);

                int crypto_function_ret =
                    crypto_function(int(in_byte_cnt), &operation->bytes_to_process[block_index],
                        &bytes[0], operation->rsa, RSA_PKCS1_PADDING);
                if (crypto_function_ret == -1)
                {
                    operation->error();
                    return;
                }

                auto out_byte_cnt = size_t(crypto_function_ret);
                bytes.resize(out_byte_cnt);
                partial_result.reserve(partial_result.size() + out_byte_cnt);
                std::copy(bytes.cbegin(), bytes.cend(), std::back_inserter(partial_result));
            }

            operation->completion(job_index, std::move(partial_result));
        });
        first_block = last_block + 1;
    }

    return future;
}

RSACipherImpl::CipherOperation::CipherOperation(std::promise<ByteVector> &&a_promise, RSA *a_rsa,
    BIO *a_key_bio, ByteVector a_bytes_to_process, size_t a_key_len, size_t a_block_len,
    int a_job_count)
    : promise {std::move(a_promise)}
    , rsa {a_rsa}
    , key_bio {a_key_bio}
    , bytes_to_process {std::move(a_bytes_to_process)}
    , key_len {a_key_len}
    , block_len {a_block_len}
    , pending_jobs {a_job_count}
    , error_signaled {false}
{
}

void RSACipherImpl::CipherOperation::completion(int job_index, ByteVector &&partial_result)
{
    std::lock_guard<std::mutex> lock {mutex};

    if (error_signaled)
    {
        return;
    }

    partial_results.emplace(job_index, std::move(partial_result));
    if (--pending_jobs == 0)
    {
        size_t     total_size = std::accumulate(partial_results.cbegin(), partial_results.cend(),
            size_t(0), [](size_t total, const auto &next) { return total + next.second.size(); });
        ByteVector result;
        result.reserve(total_size);
        for (const auto &kv : partial_results)
        {
            std::copy(kv.second.cbegin(), kv.second.cend(), std::back_inserter(result));
        }

        promise.set_value(result);
        cleanup();
    }
}

void RSACipherImpl::CipherOperation::error()
{
    std::lock_guard<std::mutex> lock {mutex};

    if (error_signaled)
    {
        return;
    }

    promise.set_value({});
    cleanup();
    error_signaled = true;
}

void RSACipherImpl::CipherOperation::cleanup() const
{
    BIO_vfree(key_bio);
    RSA_free(rsa);
}
}  // namespace sand::crypto
