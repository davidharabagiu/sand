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

namespace sand::protocol
{
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
    INITDOWNLOAD    = 101
};

struct Message
{
    const RequestCode request_code;

    explicit Message(RequestCode code)
        : request_code {code}
    {
    }

    virtual ~Message() = default;
    virtual std::vector<Byte> serialize(
        const std::shared_ptr<const MessageSerializer> &serializer) const = 0;
};

struct PullMessage : public Message
{
    uint8_t address_count;

    PullMessage()
        : Message {RequestCode::PULL}
    {
    }

    std::vector<Byte> serialize(
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

    std::vector<Byte> serialize(
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

    std::vector<Byte> serialize(
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

    std::vector<Byte> serialize(
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

    std::vector<Byte> serialize(
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
        network::IPv4Address address;
        enum
        {
            ADD_ADDRESS,
            REMOVE_ADDRESS
        } action;
    };

    std::vector<Entry> entries;

    DNLSyncMessage()
        : Message {RequestCode::DNLSYNC}
    {
    }

    std::vector<Byte> serialize(
        const std::shared_ptr<const MessageSerializer> &serializer) const override
    {
        return serializer->serialize(*this);
    }
};

struct SearchMessage : public Message
{
    SearchId      search_id;
    NodePublicKey sender_public_key;
    AHash         file_hash;

    SearchMessage()
        : Message {RequestCode::SEARCH}
    {
    }

    std::vector<Byte> serialize(
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

    SearchId              search_id;
    OfferId               offer_id;
    NodePublicKey         receiver_public_key;
    TransferKey           transfer_key;
    std::vector<PartData> parts;

    OfferMessage()
        : Message {RequestCode::OFFER}
    {
    }

    std::vector<Byte> serialize(
        const std::shared_ptr<const MessageSerializer> &serializer) const override
    {
        return serializer->serialize(*this);
    }
};

struct UncacheMessage : public Message
{
    AHash file_hash;

    UncacheMessage()
        : Message {RequestCode::UNCACHE}
    {
    }

    std::vector<Byte> serialize(
        const std::shared_ptr<const MessageSerializer> &serializer) const override
    {
        return serializer->serialize(*this);
    }
};

struct ConfirmTransferMessage : public Message
{
    OfferId offer_id;

    ConfirmTransferMessage()
        : Message {RequestCode::CONFIRMTRANSFER}
    {
    }

    std::vector<Byte> serialize(
        const std::shared_ptr<const MessageSerializer> &serializer) const override
    {
        return serializer->serialize(*this);
    }
};

struct RequestProxyMessage : public Message
{
    PartSize part_size;

    RequestProxyMessage()
        : Message {RequestCode::REQUESTPROXY}
    {
    }

    std::vector<Byte> serialize(
        const std::shared_ptr<const MessageSerializer> &serializer) const override
    {
        return serializer->serialize(*this);
    }
};

struct InitUploadMessage : public Message
{
    OfferId offer_id;

    InitUploadMessage()
        : Message {RequestCode::INITUPLOAD}
    {
    }

    std::vector<Byte> serialize(
        const std::shared_ptr<const MessageSerializer> &serializer) const override
    {
        return serializer->serialize(*this);
    }
};

struct UploadMessage : public Message
{
    PartSize          offset;
    std::vector<Byte> data;

    UploadMessage()
        : Message {RequestCode::UPLOAD}
    {
    }

    std::vector<Byte> serialize(
        const std::shared_ptr<const MessageSerializer> &serializer) const override
    {
        return serializer->serialize(*this);
    }
};

struct FetchMessage : public Message
{
    OfferId              offer_id;
    network::IPv4Address drop_point;

    FetchMessage()
        : Message {RequestCode::FETCH}
    {
    }

    std::vector<Byte> serialize(
        const std::shared_ptr<const MessageSerializer> &serializer) const override
    {
        return serializer->serialize(*this);
    }
};

struct InitDownloadMessage : public Message
{
    OfferId offer_id;

    InitDownloadMessage()
        : Message {RequestCode::INITDOWNLOAD}
    {
    }

    std::vector<Byte> serialize(
        const std::shared_ptr<const MessageSerializer> &serializer) const override
    {
        return serializer->serialize(*this);
    }
};

enum class StatusCode : uint8_t
{
    OK          = 0,
    UNREACHABLE = 1
};

struct BasicReply
{
    StatusCode status_code;

    virtual ~BasicReply() = default;

    virtual std::vector<Byte> serialize(
        const std::shared_ptr<const MessageSerializer> &serializer) const
    {
        return serializer->serialize(*this);
    }
};

struct PullReply : public BasicReply
{
    std::vector<network::IPv4Address> peers;

    std::vector<Byte> serialize(
        const std::shared_ptr<const MessageSerializer> &serializer) const override
    {
        return serializer->serialize(*this);
    }
};

template<RequestCode>
struct ReplyType
{
    using type = BasicReply;
};

template<>
struct ReplyType<RequestCode::PULL>
{
    using type = PullReply;
};

template<RequestCode C>
using ReplyType_t = typename ReplyType<C>::type;

}  // namespace sand::protocol

#endif  // SAND_PROTOCOL_MESSAGES_HPP_
