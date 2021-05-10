#ifndef SAND_TEST_RSACIPHER_MOCK_HPP_
#define SAND_TEST_RSACIPHER_MOCK_HPP_

#include <gmock/gmock.h>

#include "rsacipher.hpp"

using namespace ::sand::crypto;
using namespace ::sand::utils;

class RSACipherMock : public RSACipher
{
public:
    MOCK_METHOD(std::future<bool>, generate_key_pair,
        (ModulusSize, PublicExponent, Key &, Key &, Executer &), (const, override));
    MOCK_METHOD(std::future<ByteVector>, encrypt,
        (const Key &, const ByteVector &, Executer &, int), (const, override));
    MOCK_METHOD(std::future<ByteVector>, decrypt,
        (const Key &, const ByteVector &, Executer &, int), (const, override));
};

#endif  // SAND_TEST_RSACIPHER_MOCK_HPP_
