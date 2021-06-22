#include "sha3hasherimpl.hpp"

#include <algorithm>
#include <iterator>

namespace sand::crypto
{
using IStreamBufIt = std::istreambuf_iterator<SHA3Hasher::Byte, std::char_traits<SHA3Hasher::Byte>>;

std::vector<SHA3Hasher::Byte> SHA3HasherImpl::hash(SHA3_224_t, const Byte *data, size_t len)
{
    return hash(
        EVP_sha3_224(), SHA224_DIGEST_LENGTH, data, data + len, std::min(len, DEFAULT_BUFFER_SIZE));
}

std::vector<SHA3Hasher::Byte> SHA3HasherImpl::hash(SHA3_256_t, const Byte *data, size_t len)
{
    return hash(
        EVP_sha3_256(), SHA256_DIGEST_LENGTH, data, data + len, std::min(len, DEFAULT_BUFFER_SIZE));
}

std::vector<SHA3Hasher::Byte> SHA3HasherImpl::hash(SHA3_384_t, const Byte *data, size_t len)
{
    return hash(
        EVP_sha3_384(), SHA384_DIGEST_LENGTH, data, data + len, std::min(len, DEFAULT_BUFFER_SIZE));
}

std::vector<SHA3Hasher::Byte> SHA3HasherImpl::hash(SHA3_512_t, const Byte *data, size_t len)
{
    return hash(
        EVP_sha3_512(), SHA512_DIGEST_LENGTH, data, data + len, std::min(len, DEFAULT_BUFFER_SIZE));
}

std::vector<SHA3Hasher::Byte> SHA3HasherImpl::hash(
    SHA3Hasher::SHA3_224_t, SHA3Hasher::InputStream &is)
{
    return hash(EVP_sha3_224(), SHA224_DIGEST_LENGTH, IStreamBufIt {is}, IStreamBufIt {});
}

std::vector<SHA3Hasher::Byte> SHA3HasherImpl::hash(
    SHA3Hasher::SHA3_256_t, SHA3Hasher::InputStream &is)
{
    return hash(EVP_sha3_256(), SHA256_DIGEST_LENGTH, IStreamBufIt {is}, IStreamBufIt {});
}

std::vector<SHA3Hasher::Byte> SHA3HasherImpl::hash(
    SHA3Hasher::SHA3_384_t, SHA3Hasher::InputStream &is)
{
    return hash(EVP_sha3_384(), SHA384_DIGEST_LENGTH, IStreamBufIt {is}, IStreamBufIt {});
}

std::vector<SHA3Hasher::Byte> SHA3HasherImpl::hash(
    SHA3Hasher::SHA3_512_t, SHA3Hasher::InputStream &is)
{
    return hash(EVP_sha3_512(), SHA512_DIGEST_LENGTH, IStreamBufIt {is}, IStreamBufIt {});
}
}  // namespace sand::crypto
