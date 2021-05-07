#ifndef SAND_PROTOCOL_SECRETDATAINTERPRETERIMPL_HPP_
#define SAND_PROTOCOL_SECRETDATAINTERPRETERIMPL_HPP_

#include <memory>

#include "secretdatainterpreter.hpp"

namespace sand::protocol
{
class SecretDataInterpreterImpl : public SecretDataInterpreter
{
public:
    explicit SecretDataInterpreterImpl(std::shared_ptr<const crypto::RSACipher> rsa);

    [[nodiscard]] std::pair<OfferMessage::SecretData, bool> decrypt_offer_message(
        const std::vector<Byte> &     encrypted,
        const crypto::RSACipher::Key &private_key) const override;
    [[nodiscard]] std::vector<Byte> encrypt_offer_message(const OfferMessage::SecretData &secret,
        const crypto::RSACipher::Key &public_key) const override;

private:
    const std::shared_ptr<const crypto::RSACipher> rsa_;
};
}  // namespace sand::protocol

#endif  // SAND_PROTOCOL_SECRETDATAINTERPRETERIMPL_HPP_
