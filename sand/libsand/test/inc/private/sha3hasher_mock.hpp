#ifndef SAND_TEST_SHA3HASHER_MOCK_HPP_
#define SAND_TEST_SHA3HASHER_MOCK_HPP_

#include <gmock/gmock.h>

#include "sha3hasher.hpp"

using namespace ::sand::crypto;

class SHA3HasherMock : public SHA3Hasher
{
public:
    MOCK_METHOD(std::vector<Byte>, hash, (SHA3_224_t, const Byte *, size_t), (override));
    MOCK_METHOD(std::vector<Byte>, hash, (SHA3_256_t, const Byte *, size_t), (override));
    MOCK_METHOD(std::vector<Byte>, hash, (SHA3_384_t, const Byte *, size_t), (override));
    MOCK_METHOD(std::vector<Byte>, hash, (SHA3_512_t, const Byte *, size_t), (override));
    MOCK_METHOD(std::vector<Byte>, hash, (SHA3_224_t, InputStream &), (override));
    MOCK_METHOD(std::vector<Byte>, hash, (SHA3_256_t, InputStream &), (override));
    MOCK_METHOD(std::vector<Byte>, hash, (SHA3_384_t, InputStream &), (override));
    MOCK_METHOD(std::vector<Byte>, hash, (SHA3_512_t, InputStream &), (override));
};

#endif  // SAND_TEST_SHA3HASHER_MOCK_HPP_
