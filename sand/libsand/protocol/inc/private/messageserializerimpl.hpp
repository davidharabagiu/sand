#ifndef SAND_PROTOCOL_MESSAGESERIALIZERIMPL_HPP_
#define SAND_PROTOCOL_MESSAGESERIALIZERIMPL_HPP_

#include "messageserializer.hpp"

namespace sand::protocol
{
class MessageSerializerImpl : public MessageSerializer
{
public:
    std::vector<uint8_t> serialize(const PullMessage &message) const override;
    std::vector<uint8_t> serialize(const PushMessage &message) const override;
    std::vector<uint8_t> serialize(const ByeMessage &message) const override;
    std::vector<uint8_t> serialize(const DeadMessage &message) const override;
    std::vector<uint8_t> serialize(const PingMessage &message) const override;
    std::vector<uint8_t> serialize(const DNLSyncMessage &message) const override;
    std::vector<uint8_t> serialize(const SearchMessage &message) const override;
    std::vector<uint8_t> serialize(const OfferMessage &message) const override;
    std::vector<uint8_t> serialize(const UncacheMessage &message) const override;
    std::vector<uint8_t> serialize(const ConfirmTransferMessage &message) const override;
    std::vector<uint8_t> serialize(const RequestProxyMessage &message) const override;
    std::vector<uint8_t> serialize(const InitUploadMessage &message) const override;
    std::vector<uint8_t> serialize(const UploadMessage &message) const override;
    std::vector<uint8_t> serialize(const FetchMessage &message) const override;
    std::vector<uint8_t> serialize(const InitDownloadMessage &message) const override;
    std::vector<uint8_t> serialize(const BasicReply &message) const override;
    std::vector<uint8_t> serialize(const PullReply &message) const override;

    void deserialize(const std::vector<uint8_t> &bytes,
        RequestDeserializationResultReceptor &   receptor) const override;

    bool deserialize(const std::vector<uint8_t> &bytes, BasicReply &reply) const override;
    bool deserialize(const std::vector<uint8_t> &bytes, PullReply &reply) const override;
};

}  // namespace sand::protocol

#endif  // SAND_PROTOCOL_MESSAGESERIALIZERIMPL_HPP_
