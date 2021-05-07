#ifndef SAND_PROTOCOL_MESSAGESERIALIZERIMPL_HPP_
#define SAND_PROTOCOL_MESSAGESERIALIZERIMPL_HPP_

#include <memory>

#include "messageserializer.hpp"
#include "rsacipher.hpp"

namespace sand::protocol
{
class MessageSerializerImpl : public MessageSerializer
{
public:
    [[nodiscard]] std::vector<uint8_t> serialize(const PullMessage &message) const override;
    [[nodiscard]] std::vector<uint8_t> serialize(const PushMessage &message) const override;
    [[nodiscard]] std::vector<uint8_t> serialize(const ByeMessage &message) const override;
    [[nodiscard]] std::vector<uint8_t> serialize(const DeadMessage &message) const override;
    [[nodiscard]] std::vector<uint8_t> serialize(const PingMessage &message) const override;
    [[nodiscard]] std::vector<uint8_t> serialize(const DNLSyncMessage &message) const override;
    [[nodiscard]] std::vector<uint8_t> serialize(const SearchMessage &message) const override;
    [[nodiscard]] std::vector<uint8_t> serialize(const OfferMessage &message) const override;
    [[nodiscard]] std::vector<uint8_t> serialize(const UncacheMessage &message) const override;
    [[nodiscard]] std::vector<uint8_t> serialize(
        const ConfirmTransferMessage &message) const override;
    [[nodiscard]] std::vector<uint8_t> serialize(const RequestProxyMessage &message) const override;
    [[nodiscard]] std::vector<uint8_t> serialize(const InitUploadMessage &message) const override;
    [[nodiscard]] std::vector<uint8_t> serialize(const UploadMessage &message) const override;
    [[nodiscard]] std::vector<uint8_t> serialize(const FetchMessage &message) const override;
    [[nodiscard]] std::vector<uint8_t> serialize(const InitDownloadMessage &message) const override;
    [[nodiscard]] std::vector<uint8_t> serialize(const BasicReply &message) const override;
    [[nodiscard]] std::vector<uint8_t> serialize(const PullReply &message) const override;

    void deserialize(const std::vector<uint8_t> &bytes,
        MessageDeserializationResultReceptor &   receptor) const override;
};

}  // namespace sand::protocol

#endif  // SAND_PROTOCOL_MESSAGESERIALIZERIMPL_HPP_
