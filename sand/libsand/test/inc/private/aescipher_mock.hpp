#ifndef SAND_TEST_AESCIPHER_MOCK_HPP_
#define SAND_TEST_AESCIPHER_MOCK_HPP_

#include <gmock/gmock.h>

#include "aescipher.hpp"

using namespace ::sand::crypto;
using namespace ::sand::utils;

class AESCipherMock : public AESCipher
{
public:
    MOCK_METHOD(bool, generate_key_and_iv, (KeySize, ModeOfOperation, ByteVector &, ByteVector &),
        (const, override));
    MOCK_METHOD(std::future<ByteVector>, encrypt,
        (ModeOfOperation, const ByteVector &, const ByteVector &, const ByteVector &, Executer &),
        (override));
    MOCK_METHOD(std::future<ByteVector>, decrypt,
        (ModeOfOperation, const ByteVector &, const ByteVector &, const ByteVector &, Executer &),
        (override));
};

#endif  // SAND_TEST_AESCIPHER_MOCK_HPP_
