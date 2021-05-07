#ifndef SAND_TEST_RSACIPHER_MOCK_HPP_
#define SAND_TEST_RSACIPHER_MOCK_HPP_

#include <gmock/gmock.h>

#include "rsacipher.hpp"

using namespace sand::crypto;

class RSACipherMock : public RSACipher
{
public:
    MOCK_METHOD(
        (std::pair<Key, Key>), generate_key_pair, (size_t, uint_least64_t), (const, override));
    MOCK_METHOD(ByteVector, encrypt, (const Key &, const ByteVector &), (const, override));
    MOCK_METHOD(ByteVector, decrypt, (const Key &, const ByteVector &), (const, override));
};

#endif  // SAND_TEST_RSACIPHER_MOCK_HPP_
