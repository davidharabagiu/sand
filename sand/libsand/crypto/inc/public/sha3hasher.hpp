#ifndef SAND_CRYPTO_SHA3HASHER_HPP_
#define SAND_CRYPTO_SHA3HASHER_HPP_

#include <istream>
#include <vector>

namespace sand::crypto
{
struct SHA3_224_t
{};
constexpr SHA3_224_t SHA3_224 {};

struct SHA3_256_t
{};
constexpr SHA3_256_t SHA3_256 {};

struct SHA3_384_t
{};
constexpr SHA3_384_t SHA3_384 {};

struct SHA3_512_t
{};
constexpr SHA3_512_t SHA3_512 {};

class SHA3Hasher
{
public:
    using Byte        = uint8_t;
    using InputStream = std::istream;

    virtual ~SHA3Hasher() = default;

    virtual std::vector<Byte> hash(SHA3_224_t, const Byte *data, size_t len) = 0;
    virtual std::vector<Byte> hash(SHA3_256_t, const Byte *data, size_t len) = 0;
    virtual std::vector<Byte> hash(SHA3_384_t, const Byte *data, size_t len) = 0;
    virtual std::vector<Byte> hash(SHA3_512_t, const Byte *data, size_t len) = 0;
    virtual std::vector<Byte> hash(SHA3_224_t, InputStream &is)              = 0;
    virtual std::vector<Byte> hash(SHA3_256_t, InputStream &is)              = 0;
    virtual std::vector<Byte> hash(SHA3_384_t, InputStream &is)              = 0;
    virtual std::vector<Byte> hash(SHA3_512_t, InputStream &is)              = 0;
};
}  // namespace sand::crypto

#endif  // SAND_CRYPTO_SHA3HASHER_HPP_
