#include "messageserializerimpl.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iterator>
#include <limits>
#include <type_traits>

#include <glog/logging.h>

#include "messagedeserializationresultreceptor.hpp"
#include "messages.hpp"

namespace sand::protocol
{
namespace
{
template<typename T, typename OutputIt>
static auto serialize_field(const T &field, OutputIt dest)
    -> std::enable_if_t<std::is_pod_v<T>, OutputIt>
{
    auto b = reinterpret_cast<const uint8_t *>(&field);
    auto e = b + sizeof(T);
#ifdef IS_BIG_ENDIAN
    return std::copy(std::make_reverse_iterator(e), std::make_reverse_iterator(b), dest);
#else
    return std::copy(b, e, dest);
#endif  // IS_BIG_ENDIAN
}

template<typename Iterator>
static auto check_distance(Iterator begin, size_t dist, Iterator end)
    -> std::enable_if_t<std::is_same_v<typename std::iterator_traits<Iterator>::iterator_category,
                            std::random_access_iterator_tag>,
        bool>
{
    std::advance(begin, dist);
    if (std::distance(begin, end) < 0)
    {
        LOG(WARNING) << "Cannot read past end iterator";
        return false;
    }
    return true;
}

template<typename T, typename InputIt>
static auto deserialize_field(T &field, InputIt src_begin, InputIt src_end, bool &ok)
    -> std::enable_if_t<std::is_pod_v<T>, InputIt>
{
    if (!check_distance(src_begin, sizeof(T), src_end))
    {
        ok = false;
        return src_begin;
    }

    auto dest = reinterpret_cast<uint8_t *>(&field);

#ifdef IS_BIG_ENDIAN
    std::copy_n(std::make_reverse_iterator(src_begin), src_count, dest);
#else
    std::copy_n(src_begin, sizeof(T), dest);
#endif  // IS_BIG_ENDIAN
    std::advance(src_begin, sizeof(T));

    ok = true;
    return src_begin;
}

template<typename InputIt>
static InputIt deserialize_payload(
    PullMessage &message, InputIt src_begin, InputIt src_end, bool &ok)
{
    ok        = true;
    src_begin = deserialize_field(message.address_count, src_begin, src_end, ok);
    return src_begin;
}

template<typename InputIt>
static InputIt deserialize_payload(
    DeadMessage &message, InputIt src_begin, InputIt src_end, bool &ok)
{
    ok = true;
    uint8_t address_count;
    src_begin = deserialize_field(address_count, src_begin, src_end, ok);
    if (!ok)
    {
        return src_begin;
    }
    message.nodes.resize(address_count);
    for (auto &addr : message.nodes)
    {
        src_begin = deserialize_field(addr, src_begin, src_end, ok);
        if (!ok)
        {
            return src_begin;
        }
    }
    return src_begin;
}

template<typename InputIt>
static InputIt deserialize_payload(
    DNLSyncMessage &message, InputIt src_begin, InputIt src_end, bool &ok)
{
    ok = true;
    uint8_t entry_count;
    src_begin = deserialize_field(entry_count, src_begin, src_end, ok);
    if (!ok)
    {
        return src_begin;
    }
    message.entries.resize(entry_count);
    for (auto &entry : message.entries)
    {
        uint64_t ts;

        src_begin = deserialize_field(ts, src_begin, src_end, ok);
        if (!ok)
        {
            return src_begin;
        }

        src_begin = deserialize_field(entry.address, src_begin, src_end, ok);
        if (!ok)
        {
            return src_begin;
        }

        src_begin = deserialize_field(entry.action, src_begin, src_end, ok);
        if (!ok)
        {
            return src_begin;
        }

        entry.timestamp = Timestamp(std::chrono::milliseconds(ts));
    }
    return src_begin;
}

template<typename InputIt>
static InputIt deserialize_payload(
    SearchMessage &message, InputIt src_begin, InputIt src_end, bool &ok)
{
    ok        = true;
    src_begin = deserialize_field(message.search_id, src_begin, src_end, ok);
    if (!ok)
    {
        return src_begin;
    }

    if (!check_distance(src_begin, 128, src_end))
    {
        ok = false;
        return src_begin;
    }
    std::copy_n(src_begin, 128, message.sender_public_key.begin());
    std::advance(src_begin, 128);

    if (!check_distance(src_begin, 92, src_end))
    {
        ok = false;
        return src_begin;
    }
    std::copy_n(src_begin, 92, message.file_hash.begin());
    std::advance(src_begin, 92);

    return src_begin;
}

template<typename InputIt>
static InputIt deserialize_payload(
    OfferMessage & /*message*/, InputIt src_begin, InputIt /*src_end*/, bool &ok)
{
    // TBI
    ok = true;
    return src_begin;
}

template<typename InputIt>
static InputIt deserialize_payload(
    UncacheMessage &message, InputIt src_begin, InputIt src_end, bool &ok)
{
    ok = true;

    if (!check_distance(src_begin, 92, src_end))
    {
        ok = false;
        return src_begin;
    }
    std::copy_n(src_begin, 92, message.file_hash.begin());
    std::advance(src_begin, 92);

    return src_begin;
}

template<typename InputIt>
static InputIt deserialize_payload(
    ConfirmTransferMessage &message, InputIt src_begin, InputIt src_end, bool &ok)
{
    ok        = true;
    src_begin = deserialize_field(message.offer_id, src_begin, src_end, ok);
    return src_begin;
}

template<typename InputIt>
static InputIt deserialize_payload(
    RequestProxyMessage &message, InputIt src_begin, InputIt src_end, bool &ok)
{
    ok        = true;
    src_begin = deserialize_field(message.part_size, src_begin, src_end, ok);
    return src_begin;
}

template<typename InputIt>
static InputIt deserialize_payload(
    InitUploadMessage &message, InputIt src_begin, InputIt src_end, bool &ok)
{
    ok        = true;
    src_begin = deserialize_field(message.offer_id, src_begin, src_end, ok);
    return src_begin;
}

template<typename InputIt>
static InputIt deserialize_payload(
    UploadMessage &message, InputIt src_begin, InputIt src_end, bool &ok)
{
    ok = true;

    src_begin = deserialize_field(message.offset, src_begin, src_end, ok);
    if (!ok)
    {
        return src_begin;
    }

    uint32_t data_size;
    src_begin = deserialize_field(data_size, src_begin, src_end, ok);
    if (!ok)
    {
        return src_begin;
    }

    if (!check_distance(src_begin, data_size, src_end))
    {
        ok = false;
        return src_begin;
    }
    message.data.resize(data_size);
    std::copy_n(src_begin, data_size, message.data.begin());
    std::advance(src_begin, data_size);

    return src_begin;
}

template<typename InputIt>
static InputIt deserialize_payload(
    FetchMessage &message, InputIt src_begin, InputIt src_end, bool &ok)
{
    ok = true;

    src_begin = deserialize_field(message.offer_id, src_begin, src_end, ok);
    if (!ok)
    {
        return src_begin;
    }
    src_begin = deserialize_field(message.drop_point, src_begin, src_end, ok);

    return src_begin;
}

template<typename InputIt>
static InputIt deserialize_payload(
    InitDownloadMessage &message, InputIt src_begin, InputIt src_end, bool &ok)
{
    ok        = true;
    src_begin = deserialize_field(message.offer_id, src_begin, src_end, ok);
    return src_begin;
}

template<typename InputIt>
static InputIt deserialize_payload(PullReply &message, InputIt src_begin, InputIt src_end, bool &ok)
{
    ok = true;

    uint8_t address_count;
    src_begin = deserialize_field(address_count, src_begin, src_end, ok);
    if (!ok)
    {
        return src_begin;
    }
    message.peers.resize(address_count);
    for (auto &addr : message.peers)
    {
        src_begin = deserialize_field(addr, src_begin, src_end, ok);
        if (!ok)
        {
            return src_begin;
        }
    }

    return src_begin;
}
}  // namespace

std::vector<uint8_t> MessageSerializerImpl::serialize(const PullMessage &message) const
{
    std::vector<uint8_t> out(
        sizeof(message.message_code) + sizeof(message.request_id) + sizeof(message.address_count));

    auto dest = out.begin();
    dest      = serialize_field(message.message_code, dest);
    dest      = serialize_field(message.request_id, dest);
    serialize_field(message.address_count, dest);

    return out;
}

std::vector<uint8_t> MessageSerializerImpl::serialize(const PushMessage &message) const
{
    std::vector<uint8_t> out(sizeof(message.message_code) + sizeof(message.request_id));

    auto dest = out.begin();
    dest      = serialize_field(message.message_code, dest);
    serialize_field(message.request_id, dest);

    return out;
}

std::vector<uint8_t> MessageSerializerImpl::serialize(const ByeMessage &message) const
{
    std::vector<uint8_t> out(sizeof(message.message_code) + sizeof(message.request_id));

    auto dest = out.begin();
    dest      = serialize_field(message.message_code, dest);
    serialize_field(message.request_id, dest);

    return out;
}

std::vector<uint8_t> MessageSerializerImpl::serialize(const DeadMessage &message) const
{
    using ListSizeT = uint8_t;

    std::vector<uint8_t> out(sizeof(message.message_code) + sizeof(message.request_id) +
                             sizeof(ListSizeT) + message.nodes.size() * sizeof(message.nodes[0]));

    auto dest = out.begin();
    dest      = serialize_field(message.message_code, dest);
    dest      = serialize_field(message.request_id, dest);
    dest      = serialize_field(
        ListSizeT(std::min(size_t(std::numeric_limits<ListSizeT>::max()), message.nodes.size())),
        dest);
    for (auto addr : message.nodes)
    {
        dest = serialize_field(addr, dest);
    }

    return out;
}

std::vector<uint8_t> MessageSerializerImpl::serialize(const PingMessage &message) const
{
    std::vector<uint8_t> out(sizeof(message.message_code) + sizeof(message.request_id));

    auto dest = out.begin();
    dest      = serialize_field(message.message_code, dest);
    serialize_field(message.request_id, dest);

    return out;
}

std::vector<uint8_t> MessageSerializerImpl::serialize(const DNLSyncMessage &message) const
{
    using ListSizeT  = uint8_t;
    using TimestampT = uint64_t;

    size_t entry_size =
        sizeof(message.entries[0].address) + sizeof(message.entries[0].action) + sizeof(TimestampT);
    std::vector<uint8_t> out(sizeof(message.message_code) + sizeof(message.request_id) +
                             sizeof(ListSizeT) + message.entries.size() * entry_size);

    auto dest = out.begin();
    dest      = serialize_field(message.message_code, dest);
    dest      = serialize_field(message.request_id, dest);
    dest      = serialize_field(
        ListSizeT(std::min(size_t(std::numeric_limits<ListSizeT>::max()), message.entries.size())),
        dest);
    for (auto entry : message.entries)
    {
        dest = serialize_field(TimestampT(std::chrono::duration_cast<std::chrono::milliseconds>(
                                   entry.timestamp.time_since_epoch())
                                              .count()),
            dest);
        dest = serialize_field(entry.address, dest);
        dest = serialize_field(entry.action, dest);
    }

    return out;
}

std::vector<uint8_t> MessageSerializerImpl::serialize(const SearchMessage &message) const
{
    std::vector<uint8_t> out(sizeof(message.message_code) + sizeof(message.request_id) +
                             sizeof(message.search_id) + sizeof(message.sender_public_key) +
                             sizeof(message.file_hash));

    auto dest = out.begin();
    dest      = serialize_field(message.message_code, dest);
    dest      = serialize_field(message.request_id, dest);
    dest      = serialize_field(message.search_id, dest);
    dest = std::copy(message.sender_public_key.cbegin(), message.sender_public_key.cend(), dest);
    std::copy(message.file_hash.cbegin(), message.file_hash.cend(), dest);

    return out;
}

std::vector<uint8_t> MessageSerializerImpl::serialize(const OfferMessage & /*message*/) const
{
    // TBI
    return std::vector<uint8_t>();
}

std::vector<uint8_t> MessageSerializerImpl::serialize(const UncacheMessage &message) const
{
    std::vector<uint8_t> out(
        sizeof(message.message_code) + sizeof(message.request_id) + sizeof(message.file_hash));

    auto dest = out.begin();
    dest      = serialize_field(message.message_code, dest);
    dest      = serialize_field(message.request_id, dest);
    std::copy(message.file_hash.cbegin(), message.file_hash.cend(), dest);

    return out;
}

std::vector<uint8_t> MessageSerializerImpl::serialize(const ConfirmTransferMessage &message) const
{
    std::vector<uint8_t> out(
        sizeof(message.message_code) + sizeof(message.request_id) + sizeof(message.offer_id));

    auto dest = out.begin();
    dest      = serialize_field(message.message_code, dest);
    dest      = serialize_field(message.request_id, dest);
    serialize_field(message.offer_id, dest);

    return out;
}

std::vector<uint8_t> MessageSerializerImpl::serialize(const RequestProxyMessage &message) const
{
    std::vector<uint8_t> out(
        sizeof(message.message_code) + sizeof(message.request_id) + sizeof(message.part_size));

    auto dest = out.begin();
    dest      = serialize_field(message.message_code, dest);
    dest      = serialize_field(message.request_id, dest);
    serialize_field(message.part_size, dest);

    return out;
}

std::vector<uint8_t> MessageSerializerImpl::serialize(const InitUploadMessage &message) const
{
    std::vector<uint8_t> out(
        sizeof(message.message_code) + sizeof(message.request_id) + sizeof(message.offer_id));

    auto dest = out.begin();
    dest      = serialize_field(message.message_code, dest);
    dest      = serialize_field(message.request_id, dest);
    serialize_field(message.offer_id, dest);

    return out;
}

std::vector<uint8_t> MessageSerializerImpl::serialize(const UploadMessage &message) const
{
    std::vector<uint8_t> out(sizeof(message.message_code) + sizeof(message.request_id) +
                             sizeof(message.offset) + sizeof(PartSize) +
                             message.data.size() * sizeof(message.data[0]));

    auto dest = out.begin();
    dest      = serialize_field(message.message_code, dest);
    dest      = serialize_field(message.request_id, dest);
    dest      = serialize_field(message.offset, dest);
    dest      = serialize_field(PartSize(message.data.size()), dest);
    std::copy(message.data.cbegin(), message.data.cend(), dest);

    return out;
}

std::vector<uint8_t> MessageSerializerImpl::serialize(const FetchMessage &message) const
{
    std::vector<uint8_t> out(sizeof(message.message_code) + sizeof(message.request_id) +
                             sizeof(message.offer_id) + sizeof(message.drop_point));

    auto dest = out.begin();
    dest      = serialize_field(message.message_code, dest);
    dest      = serialize_field(message.request_id, dest);
    dest      = serialize_field(message.offer_id, dest);
    serialize_field(message.drop_point, dest);

    return out;
}

std::vector<uint8_t> MessageSerializerImpl::serialize(const InitDownloadMessage &message) const
{
    std::vector<uint8_t> out(
        sizeof(message.message_code) + sizeof(message.request_id) + sizeof(message.offer_id));

    auto dest = out.begin();
    dest      = serialize_field(message.message_code, dest);
    dest      = serialize_field(message.request_id, dest);
    serialize_field(message.offer_id, dest);

    return out;
}

std::vector<uint8_t> MessageSerializerImpl::serialize(const BasicReply &message) const
{
    std::vector<uint8_t> out(2 * sizeof(message.message_code) + sizeof(message.status_code) +
                             sizeof(message.request_id));

    auto dest = out.begin();
    dest      = serialize_field(message.message_code, dest);
    dest      = serialize_field(message.request_id, dest);
    dest      = serialize_field(message.status_code, dest);
    serialize_field(message.request_message_code, dest);

    return out;
}

std::vector<uint8_t> MessageSerializerImpl::serialize(const PullReply &message) const
{
    using ListSizeT = uint8_t;

    std::vector<uint8_t> out(2 * sizeof(message.message_code) + sizeof(message.status_code) +
                             sizeof(message.request_id) + sizeof(ListSizeT) +
                             message.peers.size() * sizeof(message.peers[0]));

    auto dest = out.begin();
    dest      = serialize_field(message.message_code, dest);
    dest      = serialize_field(message.request_id, dest);
    dest      = serialize_field(message.status_code, dest);
    dest      = serialize_field(message.request_message_code, dest);
    dest      = serialize_field(
        ListSizeT(std::min(size_t(std::numeric_limits<ListSizeT>::max()), message.peers.size())),
        dest);
    for (auto addr : message.peers)
    {
        dest = serialize_field(addr, dest);
    }

    return out;
}

void MessageSerializerImpl::deserialize(
    const std::vector<uint8_t> &bytes, MessageDeserializationResultReceptor &receptor) const
{
    auto src_begin = bytes.cbegin();
    auto src_end   = bytes.cend();
    bool ok        = true;

    MessageCode message_code;
    src_begin = deserialize_field(message_code, src_begin, src_end, ok);
    if (!ok)
    {
        receptor.error();
        return;
    }

    RequestId request_id;
    src_begin = deserialize_field(request_id, src_begin, src_end, ok);
    if (!ok)
    {
        receptor.error();
        return;
    }

    switch (message_code)
    {
        case MessageCode::PULL:
        {
            PullMessage msg;
            msg.request_id = request_id;
            deserialize_payload(msg, src_begin, src_end, ok);
            if (!ok)
            {
                receptor.error();
                return;
            }
            receptor.deserialized(msg);
            break;
        }
        case MessageCode::PUSH:
        {
            PushMessage msg;
            msg.request_id = request_id;
            receptor.deserialized(msg);
            break;
        }
        case MessageCode::BYE:
        {
            ByeMessage msg;
            msg.request_id = request_id;
            receptor.deserialized(msg);
            break;
        }
        case MessageCode::DEAD:
        {
            DeadMessage msg;
            msg.request_id = request_id;
            deserialize_payload(msg, src_begin, src_end, ok);
            if (!ok)
            {
                receptor.error();
                return;
            }
            receptor.deserialized(msg);
            break;
        }
        case MessageCode::PING:
        {
            PingMessage msg;
            msg.request_id = request_id;
            receptor.deserialized(msg);
            break;
        }
        case MessageCode::DNLSYNC:
        {
            DNLSyncMessage msg;
            msg.request_id = request_id;
            deserialize_payload(msg, src_begin, src_end, ok);
            if (!ok)
            {
                receptor.error();
                return;
            }
            receptor.deserialized(msg);
            break;
        }
        case MessageCode::SEARCH:
        {
            SearchMessage msg;
            msg.request_id = request_id;
            deserialize_payload(msg, src_begin, src_end, ok);
            if (!ok)
            {
                receptor.error();
                return;
            }
            receptor.deserialized(msg);
            break;
        }
        case MessageCode::OFFER:
        {
            OfferMessage msg;
            msg.request_id = request_id;
            deserialize_payload(msg, src_begin, src_end, ok);
            if (!ok)
            {
                receptor.error();
                return;
            }
            receptor.deserialized(msg);
            break;
        }
        case MessageCode::UNCACHE:
        {
            UncacheMessage msg;
            msg.request_id = request_id;
            deserialize_payload(msg, src_begin, src_end, ok);
            if (!ok)
            {
                receptor.error();
                return;
            }
            receptor.deserialized(msg);
            break;
        }
        case MessageCode::CONFIRMTRANSFER:
        {
            ConfirmTransferMessage msg;
            msg.request_id = request_id;
            deserialize_payload(msg, src_begin, src_end, ok);
            if (!ok)
            {
                receptor.error();
                return;
            }
            receptor.deserialized(msg);
            break;
        }
        case MessageCode::REQUESTPROXY:
        {
            RequestProxyMessage msg;
            msg.request_id = request_id;
            deserialize_payload(msg, src_begin, src_end, ok);
            if (!ok)
            {
                receptor.error();
                return;
            }
            receptor.deserialized(msg);
            break;
        }
        case MessageCode::INITUPLOAD:
        {
            InitUploadMessage msg;
            msg.request_id = request_id;
            deserialize_payload(msg, src_begin, src_end, ok);
            if (!ok)
            {
                receptor.error();
                return;
            }
            receptor.deserialized(msg);
            break;
        }
        case MessageCode::UPLOAD:
        {
            UploadMessage msg;
            msg.request_id = request_id;
            deserialize_payload(msg, src_begin, src_end, ok);
            if (!ok)
            {
                receptor.error();
                return;
            }
            receptor.deserialized(msg);
            break;
        }
        case MessageCode::FETCH:
        {
            FetchMessage msg;
            msg.request_id = request_id;
            deserialize_payload(msg, src_begin, src_end, ok);
            if (!ok)
            {
                receptor.error();
                return;
            }
            receptor.deserialized(msg);
            break;
        }
        case MessageCode::INITDOWNLOAD:
        {
            InitDownloadMessage msg;
            msg.request_id = request_id;
            deserialize_payload(msg, src_begin, src_end, ok);
            if (!ok)
            {
                receptor.error();
                return;
            }
            receptor.deserialized(msg);
            break;
        }
        case MessageCode::REPLY:
        {
            StatusCode status_code;
            src_begin = deserialize_field(status_code, src_begin, src_end, ok);
            if (!ok)
            {
                receptor.error();
                return;
            }

            MessageCode request_message_code;
            src_begin = deserialize_field(request_message_code, src_begin, src_end, ok);
            if (!ok)
            {
                receptor.error();
                return;
            }

            switch (request_message_code)
            {
                case MessageCode::PULL:
                {
                    PullReply msg;
                    msg.request_id  = request_id;
                    msg.status_code = status_code;
                    deserialize_payload(msg, src_begin, src_end, ok);
                    if (!ok)
                    {
                        receptor.error();
                        return;
                    }
                    receptor.deserialized(msg);
                    break;
                }
                default:
                {
                    BasicReply msg {request_message_code};
                    msg.request_id  = request_id;
                    msg.status_code = status_code;
                    receptor.deserialized(msg);
                    break;
                }
            }
            break;
        }
        default:
        {
            LOG(WARNING) << "Invalid request code: " << int(message_code);
            receptor.error();
            break;
        }
    }
}
}  // namespace sand::protocol
