#ifndef SAND_PROTOCOL_REPLIES_HPP_
#define SAND_PROTOCOL_REPLIES_HPP_

#include <vector>

#include "address.hpp"

namespace sand::protocol
{
enum class StatusCode
{
    OK,
    UNREACHABLE
};

struct PullReplyPayload
{
    std::vector<Address> peers;
};

template<typename Payload>
struct Reply
{
    StatusCode status_code;
    Payload    payload;
};
using BasicReply = Reply<void>;

}  // namespace sand::protocol

#endif  // SAND_PROTOCOL_REPLIES_HPP_
