#ifndef SAND_TEST_BASE64ENCODER_MOCK_HPP_
#define SAND_TEST_BASE64ENCODER_MOCK_HPP_

#include <gmock/gmock.h>

#include "base64encoder.hpp"

using namespace ::sand::crypto;

class Base64EncoderMock : public Base64Encoder
{
public:
    MOCK_METHOD(std::string, encode, (const Byte *, size_t), (override));
    MOCK_METHOD(std::vector<Byte>, decode, (const std::string &), (override));
};

#endif  // SAND_TEST_BASE64ENCODER_MOCK_HPP_
