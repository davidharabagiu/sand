#ifndef SAND_PROTOCOL_MESSAGES_HPP_
#define SAND_PROTOCOL_MESSAGES_HPP_

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
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
using NodePublicKey = std::array<Byte, 128>;
using AHash         = std::array<Byte, 92>;
using TransferKey   = std::array<Byte, 16>;
using PartSize      = uint32_t;
using FileSize      = uint64_t;

enum class RequestCode : uint8_t
{
    PULL            = 32,
    PUSH            = 33,
    BYE             = 34,
    DEAD            = 35,
    PING            = 36,
    DNLSYNC         = 37,
    SEARCH          = 64,
    OFFER           = 65,
    UNCACHE         = 66,
    CONFIRMTRANSFER = 67,
    REQUESTPROXY    = 96,
    INITUPLOAD      = 98,
    UPLOAD          = 99,
    FETCH           = 100,
    INITDOWNLOAD    = 101,
    REPLY           = 255
};

enum class StatusCode : uint8_t
{
    OK          = 0,
    UNREACHABLE = 1
};

struct Message
{
    const RequestCode request_code;
    RequestId         request_id {};

    explicit Message(RequestCode code)
        : request_code {code}
        , request_id {}
    {
    }

    virtual ~Message() = default;
    [[nodiscard]] virtual std::vector<Byte> serialize(
        const std::shared_ptr<const MessageSerializer> &serializer) const = 0;
};

struct PullMessage : public Message
{
    uint8_t address_count {};

    PullMessage()
        : Message {RequestCode::PULL}
    {
    }

    [[nodiscard]] std::vector<Byte> serialize(
        const std::shared_ptr<const MessageSerializer> &serializer) const override
    {
        return serializer->serialize(*this);
    }
};

struct PushMessage : public Message
{
    PushMessage()
        : Message {RequestCode::PUSH}
    {
    }

    [[nodiscard]] std::vector<Byte> serialize(
        const std::shared_ptr<const MessageSerializer> &serializer) const override
    {
        return serializer->serialize(*this);
    }
};

struct ByeMessage : public Message
{
    ByeMessage()
        : Message {RequestCode::BYE}
    {
    }

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
        : Message {RequestCode::DEAD}
    {
    }

    [[nodiscard]] std::vector<Byte> serialize(
        const std::shared_ptr<const MessageSerializer> &serializer) const override
    {
        return serializer->serialize(*this);
    }
};

struct PingMessage : public Message
{
    PingMessage()
        : Message {RequestCode::PING}
    {
    }

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
        : Message {RequestCode::DNLSYNC}
    {
    }

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

    SearchMessage()
        : Message {RequestCode::SEARCH}
    {
    }

    [[nodiscard]] std::vector<Byte> serialize(
        const std::shared_ptr<const MessageSerializer> &serializer) const override
    {
        return serializer->serialize(*this);
    }
};

struct OfferMessage : public Message
{
    struct PartData
    {
        network::IPv4Address drop_point;
        FileSize             part_offset;
        PartSize             part_size;
    };

    SearchId              search_id {};
    OfferId               offer_id {};
    NodePublicKey         receiver_public_key {};
    TransferKey           transfer_key {};
    std::vector<PartData> parts;

    OfferMessage()
        : Message {RequestCode::OFFER}
    {
    }

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
        : Message {RequestCode::UNCACHE}
    {
    }

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
        : Message {RequestCode::CONFIRMTRANSFER}
    {
    }

    [[nodiscard]] std::vector<Byte> serialize(
        const std::shared_ptr<const MessageSerializer> &serializer) const override
    {
        return serializer->serialize(*this);
    }
};

struct RequestProxyMessage : public Message
{
    PartSize part_size {};

    RequestProxyMessage()
        : Message {RequestCode::REQUESTPROXY}
    {
    }

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
        : Message {RequestCode::INITUPLOAD}
    {
    }

    [[nodiscard]] std::vector<Byte> serialize(
        const std::shared_ptr<const MessageSerializer> &serializer) const override
    {
        return serializer->serialize(*this);
    }
};

struct UploadMessage : public Message
{
    PartSize          offset {};
    std::vector<Byte> data;

    UploadMessage()
        : Message {RequestCode::UPLOAD}
    {
    }

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
        : Message {RequestCode::FETCH}
    {
    }

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
        : Message {RequestCode::INITDOWNLOAD}
    {
    }

    [[nodiscard]] std::vector<Byte> serialize(
        const std::shared_ptr<const MessageSerializer> &serializer) const override
    {
        return serializer->serialize(*this);
    }
};

struct BasicReply : public Message
{
    StatusCode        status_code {};
    const RequestCode source_request_code;

    explicit BasicReply(RequestCode _source_request_code)
        : Message {RequestCode::REPLY}
        , source_request_code {_source_request_code}
    {
    }

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
        : BasicReply {RequestCode::PULL}
    {
    }

    [[nodiscard]] std::vector<Byte> serialize(
        const std::shared_ptr<const MessageSerializer> &serializer) const override
    {
        return serializer->serialize(*this);
    }
};
}  // namespace sand::protocol

#endif  // SAND_PROTOCOL_MESSAGES_HPP_
