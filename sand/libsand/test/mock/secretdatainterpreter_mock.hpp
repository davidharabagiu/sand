#ifndef SAND_TEST_SECRETDATAINTERPRETER_MOCK_HPP_
#define SAND_TEST_SECRETDATAINTERPRETER_MOCK_HPP_

#include <gmock/gmock.h>

#include "secretdatainterpreter.hpp"

using namespace ::sand::protocol;
using namespace ::sand::crypto;

class SecretDataInterpreterMock : public SecretDataInterpreter
{
public:
    MOCK_METHOD((std::pair<OfferMessage::SecretData, bool>), decrypt_offer_message,
        (const std::vector<Byte> &, const RSACipher::Key &), (const, override));
    MOCK_METHOD(std::vector<Byte>, encrypt_offer_message,
        (const OfferMessage::SecretData &, const RSACipher::Key &), (const, override));
};

#endif  // SAND_TEST_SECRETDATAINTERPRETER_MOCK_HPP_
