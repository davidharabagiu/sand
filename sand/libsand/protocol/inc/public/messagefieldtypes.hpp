#ifndef SAND_PROTOCOL_MESSAGEFIELDTYPES_HPP_
#define SAND_PROTOCOL_MESSAGEFIELDTYPES_HPP_

#include <array>
#include <chrono>
#include <cstdint>
#include <vector>

#include "address.hpp"

namespace sand::protocol
{
using Timestamp     = std::chrono::time_point<std::chrono::system_clock>;
using SearchId      = uint_least64_t;
using OfferId       = uint_least64_t;
using Byte          = uint_least8_t;
using NodePublicKey = std::array<Byte, 128>;
using AHash         = std::array<Byte, 92>;
using TransferKey   = std::array<Byte, 16>;
using PartSize      = uint_least32_t;
using FileSize      = uint_least64_t;

struct DNLSyncEntry
{
    Timestamp timestamp;
    Address   address;
    enum
    {
        ADD_ADDRESS,
        REMOVE_ADDRESS
    } action;
};

struct PartData
{
    Address  drop_point;
    FileSize part_offset;
    PartSize part_size;
};

struct PullReplyPayload
{
    std::vector<Address> peers;
};

enum class StatusCode
{
    OK,
    UNREACHABLE
};

template<typename Payload>
struct Reply
{
    StatusCode status_code;
    Payload    payload;
};
using BasicReply = Reply<void>;

}  // namespace sand::protocol

#endif  // SAND_PROTOCOL_MESSAGEFIELDTYPES_HPP_
