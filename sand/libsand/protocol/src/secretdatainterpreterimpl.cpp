#include "secretdatainterpreterimpl.hpp"

#include "serializationutils.hpp"

namespace sand::protocol
{
SecretDataInterpreterImpl::SecretDataInterpreterImpl(std::shared_ptr<const crypto::RSACipher> rsa,
    std::shared_ptr<utils::Executer> crypto_job_executer)
    : rsa_ {std::move(rsa)}
    , crypto_job_executer_ {std::move(crypto_job_executer)}
{
}

std::pair<OfferMessage::SecretData, bool> SecretDataInterpreterImpl::decrypt_offer_message(
    const std::vector<Byte> &encrypted, const sand::crypto::RSACipher::Key &private_key) const
{
    bool ok             = true;
    auto decrypted_data = rsa_->decrypt(private_key, encrypted, *crypto_job_executer_).get();
    if (decrypted_data.empty())
    {
        LOG(ERROR) << "RSA decryption error";
        return {{}, false};
    }

    auto dd_begin = decrypted_data.begin();
    auto dd_end   = decrypted_data.end();

    OfferMessage::SecretData secret;

    if (!serialization::check_distance(dd_begin, secret.transfer_key.size(), dd_end))
    {
        return {{}, false};
    }
    std::copy_n(dd_begin, secret.transfer_key.size(), secret.transfer_key.begin());
    std::advance(dd_begin, secret.transfer_key.size());

    uint8_t part_count;
    dd_begin = serialization::deserialize_field(part_count, dd_begin, dd_end, ok);
    if (!ok)
    {
        return {{}, false};
    }

    secret.parts.resize(part_count);
    for (auto &part_data : secret.parts)
    {
        dd_begin = serialization::deserialize_field(part_data.drop_point, dd_begin, dd_end, ok);
        if (!ok)
        {
            return {{}, false};
        }
        dd_begin = serialization::deserialize_field(part_data.part_offset, dd_begin, dd_end, ok);
        if (!ok)
        {
            return {{}, false};
        }
        dd_begin = serialization::deserialize_field(part_data.part_size, dd_begin, dd_end, ok);
        if (!ok)
        {
            return {{}, false};
        }
    }

    return {secret, true};
}

std::vector<Byte> SecretDataInterpreterImpl::encrypt_offer_message(
    const OfferMessage::SecretData &secret, const sand::crypto::RSACipher::Key &public_key) const
{
    using ListSizeT       = uint8_t;
    size_t part_data_size = sizeof(secret.parts[0].drop_point) +
                            sizeof(secret.parts[0].part_offset) + sizeof(secret.parts[0].part_size);

    std::vector<uint8_t> to_encrypt(
        sizeof(secret.transfer_key) + sizeof(ListSizeT) + secret.parts.size() * part_data_size);

    auto dest = to_encrypt.begin();
    dest      = std::copy(secret.transfer_key.cbegin(), secret.transfer_key.cend(), dest);
    dest      = serialization::serialize_field(
        ListSizeT(std::min(size_t(std::numeric_limits<ListSizeT>::max()), secret.parts.size())),
        dest);
    for (const auto &part_data : secret.parts)
    {
        dest = serialization::serialize_field(part_data.drop_point, dest);
        dest = serialization::serialize_field(part_data.part_offset, dest);
        dest = serialization::serialize_field(part_data.part_size, dest);
    }

    auto encrypted = rsa_->encrypt(public_key, to_encrypt, *crypto_job_executer_).get();
    if (encrypted.empty())
    {
        LOG(ERROR) << "RSA encryption error";
    }
    return encrypted;
}
}  // namespace sand::protocol
