#ifndef SAND_PROTOCOL_MESSAGES_HPP_
#define SAND_PROTOCOL_MESSAGES_HPP_

#include <array>
#include <chrono>
#include <cstdint>
#include <vector>

#include "address.hpp"

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

struct PullMessage
{
    Address to;
    uint8_t address_count
};

struct PushMessage
{
    Address to;
};

struct ByeMessage
{
    Address to;
};

struct DeadMessage
{
    Address              to;
    std::vector<Address> nodes;
};

struct PingMessage
{
    Address to;
};

struct DNLSyncMessage
{
    struct Entry
    {
        Timestamp timestamp;
        Address   address;
        enum
        {
            ADD_ADDRESS,
            REMOVE_ADDRESS
        } action;
    };

    Address            to;
    std::vector<Entry> entries;
};

struct SearchMessage
{
    Address       to;
    SearchId      search_id;
    NodePublicKey sender_public_key;
    AHash         file_hash;
};

struct OfferMessage
{
    struct PartData
    {
        Address  drop_point;
        FileSize part_offset;
        PartSize part_size;
    };

    Address               to;
    SearchId              search_id;
    OfferId               offer_id;
    NodePublicKey         receiver_public_key;
    TransferKey           transfer_key;
    std::vector<PartData> parts;
};

struct UncacheMessage
{
    Address to;
    AHash   file_hash;
};

struct ConfirmTransferMessage
{
    Address to;
    OfferId offer_id;
};

struct RequestProxyMessage
{
    Address  to;
    PartSize part_size;
};

struct InitUploadMessage
{
    Address to;
    OfferId offer_id;
};

struct UploadMessage
{
    Address           to;
    PartSize          offset;
    std::vector<Byte> data;
};

struct FetchMessage
{
    Address to;
    OfferId offer_id;
    Address drop_point;
};

struct InitDownloadMessage
{
    Address to;
    OfferId offer_id;
};

}  // namespace sand::protocol

#endif  // SAND_PROTOCOL_MESSAGES_HPP_
