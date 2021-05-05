#ifndef SAND_PROTOCOL_MESSAGESERIALIZER_HPP_
#define SAND_PROTOCOL_MESSAGESERIALIZER_HPP_

#include <cstdint>
#include <vector>

#include "messages_decl.hpp"

namespace sand::protocol
{
// Forward declarations
class RequestDeserializationResultReceptor;

class MessageSerializer
{
public:
    virtual ~MessageSerializer() = default;

    virtual std::vector<uint8_t> serialize(const PullMessage &message) const            = 0;
    virtual std::vector<uint8_t> serialize(const PushMessage &message) const            = 0;
    virtual std::vector<uint8_t> serialize(const ByeMessage &message) const             = 0;
    virtual std::vector<uint8_t> serialize(const DeadMessage &message) const            = 0;
    virtual std::vector<uint8_t> serialize(const PingMessage &message) const            = 0;
    virtual std::vector<uint8_t> serialize(const DNLSyncMessage &message) const         = 0;
    virtual std::vector<uint8_t> serialize(const SearchMessage &message) const          = 0;
    virtual std::vector<uint8_t> serialize(const OfferMessage &message) const           = 0;
    virtual std::vector<uint8_t> serialize(const UncacheMessage &message) const         = 0;
    virtual std::vector<uint8_t> serialize(const ConfirmTransferMessage &message) const = 0;
    virtual std::vector<uint8_t> serialize(const RequestProxyMessage &message) const    = 0;
    virtual std::vector<uint8_t> serialize(const InitUploadMessage &message) const      = 0;
    virtual std::vector<uint8_t> serialize(const UploadMessage &message) const          = 0;
    virtual std::vector<uint8_t> serialize(const FetchMessage &message) const           = 0;
    virtual std::vector<uint8_t> serialize(const InitDownloadMessage &message) const    = 0;
    virtual std::vector<uint8_t> serialize(const BasicReply &message) const             = 0;
    virtual std::vector<uint8_t> serialize(const PullReply &message) const              = 0;

    virtual void deserialize(const std::vector<uint8_t> &bytes,
        RequestDeserializationResultReceptor &           receptor) const = 0;

    virtual bool deserialize(const std::vector<uint8_t> &bytes, BasicReply &reply) const = 0;
    virtual bool deserialize(const std::vector<uint8_t> &bytes, PullReply &reply) const  = 0;
};

}  // namespace sand::protocol

#endif  // SAND_PROTOCOL_MESSAGESERIALIZER_HPP_
