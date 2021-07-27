#ifndef SAND_PROTOCOL_MESSAGES_HPP_
#define SAND_PROTOCOL_MESSAGES_HPP_

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <type_traits>
#include <vector>

#include "address.hpp"
#include "messageserializer.hpp"
#include "random.hpp"

namespace sand::protocol
{
using RequestId     = uint64_t;
using Timestamp     = std::chrono::time_point<std::chrono::system_clock>;
using SearchId      = uint64_t;
using OfferId       = uint64_t;
using Byte          = uint8_t;
using NodePublicKey = std::string;
using AHash         = std::array<Byte, 100>;
using TransferKey   = std::array<Byte, 32>;
using PartSize      = uint32_t;
using FileSize      = uint64_t;

enum class MessageCode : uint8_t
{
    PULL             = 32,
    PUSH             = 33,
    BYE              = 34,
    DEAD             = 35,
    PING             = 36,
    DNLSYNC          = 37,
    SEARCH           = 64,
    OFFER            = 65,
    UNCACHE          = 66,
    CONFIRMTRANSFER  = 67,
    REQUESTDROPPOINT = 96,
    REQUESTLIFTPROXY = 97,
    INITUPLOAD       = 98,
    UPLOAD           = 99,
    FETCH            = 100,
    INITDOWNLOAD     = 101,
    REPLY            = 255
};

enum class StatusCode : uint8_t
{
    OK                      = 0,
    UNREACHABLE             = 1,
    RESOURCE_NOT_AVAILABLE  = 2,
    DUPLICATION             = 3,
    FOREIGN_DNL_ADDRESS     = 4,
    CANNOT_FORWARD          = 5,
    PROPAGATION_LIMIT       = 6,
    DENY                    = 7,
    LIFT_PROXY_DISCONNECTED = 8,
    INTERNAL_ERROR          = 9
};

struct Message
{
    const MessageCode message_code;
    RequestId         request_id {};

    explicit Message(MessageCode code)
        : message_code {code}
        , request_id {}
    {}

    virtual ~Message() = default;
    [[nodiscard]] virtual std::vector<Byte> serialize(
        const std::shared_ptr<const MessageSerializer> &serializer) const = 0;
};

struct PullMessage : public Message
{
    uint8_t address_count {};

    PullMessage()
        : Message {MessageCode::PULL}
    {}

    [[nodiscard]] std::vector<Byte> serialize(
        const std::shared_ptr<const MessageSerializer> &serializer) const override
    {
        return serializer->serialize(*this);
    }
};

struct PushMessage : public Message
{
    PushMessage()
        : Message {MessageCode::PUSH}
    {}

    [[nodiscard]] std::vector<Byte> serialize(
        const std::shared_ptr<const MessageSerializer> &serializer) const override
    {
        return serializer->serialize(*this);
    }
};

struct ByeMessage : public Message
{
    ByeMessage()
        : Message {MessageCode::BYE}
    {}

    [[nodiscard]] std::vector<Byte> serialize(
        const std::shared_ptr<const MessageSerializer> &serializer) const override
    {
        return serializer->serialize(*this);
    }
};

struct DeadMessage : public Message
{
    std::vector<network::IPv4Address> nodes;

    DeadMessage()
        : Message {MessageCode::DEAD}
    {}

    [[nodiscard]] std::vector<Byte> serialize(
        const std::shared_ptr<const MessageSerializer> &serializer) const override
    {
        return serializer->serialize(*this);
    }
};

struct PingMessage : public Message
{
    PingMessage()
        : Message {MessageCode::PING}
    {}

    [[nodiscard]] std::vector<Byte> serialize(
        const std::shared_ptr<const MessageSerializer> &serializer) const override
    {
        return serializer->serialize(*this);
    }
};

struct DNLSyncMessage : public Message
{
    struct Entry
    {
        Timestamp            timestamp;
        network::IPv4Address address {};
        enum : uint8_t
        {
            ADD_ADDRESS,
            REMOVE_ADDRESS
        } action {};
    };

    std::vector<Entry> entries;

    DNLSyncMessage()
        : Message {MessageCode::DNLSYNC}
    {}

    [[nodiscard]] std::vector<Byte> serialize(
        const std::shared_ptr<const MessageSerializer> &serializer) const override
    {
        return serializer->serialize(*this);
    }
};

struct SearchMessage : public Message
{
    SearchId      search_id {};
    NodePublicKey sender_public_key {};
    AHash         file_hash {};
    uint8_t       time_to_live {};

    SearchMessage()
        : Message {MessageCode::SEARCH}
    {}

    [[nodiscard]] std::vector<Byte> serialize(
        const std::shared_ptr<const MessageSerializer> &serializer) const override
    {
        return serializer->serialize(*this);
    }
};

struct OfferMessage : public Message
{
    struct SecretData
    {
        struct PartData
        {
            network::IPv4Address drop_point;
            FileSize             part_offset;
            PartSize             part_size;
        };

        TransferKey           transfer_key;
        std::vector<PartData> parts;
    };

    SearchId          search_id {};
    OfferId           offer_id {};
    std::vector<Byte> encrypted_data;

    OfferMessage()
        : Message {MessageCode::OFFER}
    {}

    [[nodiscard]] std::vector<Byte> serialize(
        const std::shared_ptr<const MessageSerializer> &serializer) const override
    {
        return serializer->serialize(*this);
    }
};

struct UncacheMessage : public Message
{
    AHash file_hash {};

    UncacheMessage()
        : Message {MessageCode::UNCACHE}
    {}

    [[nodiscard]] std::vector<Byte> serialize(
        const std::shared_ptr<const MessageSerializer> &serializer) const override
    {
        return serializer->serialize(*this);
    }
};

struct ConfirmTransferMessage : public Message
{
    OfferId offer_id {};

    ConfirmTransferMessage()
        : Message {MessageCode::CONFIRMTRANSFER}
    {}

    [[nodiscard]] std::vector<Byte> serialize(
        const std::shared_ptr<const MessageSerializer> &serializer) const override
    {
        return serializer->serialize(*this);
    }
};

struct RequestDropPointMessage : public Message
{
    PartSize part_size {};
    OfferId  offer_id;

    RequestDropPointMessage()
        : Message {MessageCode::REQUESTDROPPOINT}
    {}

    [[nodiscard]] std::vector<Byte> serialize(
        const std::shared_ptr<const MessageSerializer> &serializer) const override
    {
        return serializer->serialize(*this);
    }
};

struct RequestLiftProxyMessage : public Message
{
    PartSize part_size {};
    OfferId  offer_id;

    RequestLiftProxyMessage()
        : Message {MessageCode::REQUESTLIFTPROXY}
    {}

    [[nodiscard]] std::vector<Byte> serialize(
        const std::shared_ptr<const MessageSerializer> &serializer) const override
    {
        return serializer->serialize(*this);
    }
};

struct InitUploadMessage : public Message
{
    OfferId offer_id {};

    InitUploadMessage()
        : Message {MessageCode::INITUPLOAD}
    {}

    [[nodiscard]] std::vector<Byte> serialize(
        const std::shared_ptr<const MessageSerializer> &serializer) const override
    {
        return serializer->serialize(*this);
    }
};

struct UploadMessage : public Message
{
    OfferId           offer_id;
    PartSize          offset {};
    std::vector<Byte> data;

    UploadMessage()
        : Message {MessageCode::UPLOAD}
    {}

    [[nodiscard]] std::vector<Byte> serialize(
        const std::shared_ptr<const MessageSerializer> &serializer) const override
    {
        return serializer->serialize(*this);
    }
};

struct FetchMessage : public Message
{
    OfferId              offer_id {};
    network::IPv4Address drop_point {};

    FetchMessage()
        : Message {MessageCode::FETCH}
    {}

    [[nodiscard]] std::vector<Byte> serialize(
        const std::shared_ptr<const MessageSerializer> &serializer) const override
    {
        return serializer->serialize(*this);
    }
};

struct InitDownloadMessage : public Message
{
    OfferId offer_id {};

    InitDownloadMessage()
        : Message {MessageCode::INITDOWNLOAD}
    {}

    [[nodiscard]] std::vector<Byte> serialize(
        const std::shared_ptr<const MessageSerializer> &serializer) const override
    {
        return serializer->serialize(*this);
    }
};

struct BasicReply : public Message
{
    StatusCode        status_code {};
    const MessageCode request_message_code;

    explicit BasicReply(MessageCode _request_message_code)
        : Message {MessageCode::REPLY}
        , request_message_code {_request_message_code}
    {}

    [[nodiscard]] std::vector<Byte> serialize(
        const std::shared_ptr<const MessageSerializer> &serializer) const override
    {
        return serializer->serialize(*this);
    }
};

struct PullReply : public BasicReply
{
    std::vector<network::IPv4Address> peers;

    PullReply()
        : BasicReply {MessageCode::PULL}
    {}

    [[nodiscard]] std::vector<Byte> serialize(
        const std::shared_ptr<const MessageSerializer> &serializer) const override
    {
        return serializer->serialize(*this);
    }
};
}  // namespace sand::protocol

#endif  // SAND_PROTOCOL_MESSAGES_HPP_
