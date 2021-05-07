#ifndef SAND_PROTOCOL_SECRETDATAINTERPRETER_HPP_
#define SAND_PROTOCOL_SECRETDATAINTERPRETER_HPP_

#include <utility>

#include "messages.hpp"
#include "rsacipher.hpp"

namespace sand::protocol
{
class SecretDataInterpreter
{
public:
    virtual ~SecretDataInterpreter() = default;

    [[nodiscard]] virtual std::pair<OfferMessage::SecretData, bool> decrypt_offer_message(
        const std::vector<Byte> &encrypted, const crypto::RSACipher::Key &private_key) const = 0;
    [[nodiscard]] virtual std::vector<Byte> encrypt_offer_message(
        const OfferMessage::SecretData &secret, const crypto::RSACipher::Key &public_key) const = 0;
};
}  // namespace sand::protocol

#endif  // SAND_PROTOCOL_SECRETDATAINTERPRETER_HPP_
