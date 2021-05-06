#include "messageserializerimpl.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iterator>
#include <limits>
#include <type_traits>

#include <glog/logging.h>

#include "messages.hpp"
#include "requestdeserializationresultreceptor.hpp"

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

template<typename T, typename InputIt>
static auto deserialize_field(T &field, InputIt src_begin)
    -> std::enable_if_t<std::is_pod_v<T>, InputIt>
{
    auto dest = reinterpret_cast<uint8_t *>(&field);
#ifdef IS_BIG_ENDIAN
    std::copy_n(std::make_reverse_iterator(src_begin), src_count, dest);
#else
    std::copy_n(src_begin, sizeof(T), dest);
#endif  // IS_BIG_ENDIAN
    std::advance(src_begin, sizeof(T));
    return src_begin;
}

template<typename InputIt>
static InputIt deserialize_payload(PullMessage &message, InputIt src)
{
    src = deserialize_field(message.address_count, src);
    return src;
}

template<typename InputIt>
static InputIt deserialize_payload(DeadMessage &message, InputIt src)
{
    uint8_t address_count;
    src = deserialize_field(address_count, src);
    message.nodes.resize(address_count);
    for (auto &addr : message.nodes)
    {
        src = deserialize_field(addr, src);
    }
    return src;
}

template<typename InputIt>
static InputIt deserialize_payload(DNLSyncMessage &message, InputIt src)
{
    uint8_t entry_count;
    src = deserialize_field(entry_count, src);
    message.entries.resize(entry_count);
    for (auto &entry : message.entries)
    {
        uint64_t ts;
        src = deserialize_field(ts, src);
        src = deserialize_field(entry.address, src);
        src = deserialize_field(entry.action, src);

        entry.timestamp = Timestamp(std::chrono::milliseconds(ts));
    }
    return src;
}

template<typename InputIt>
static InputIt deserialize_payload(SearchMessage &message, InputIt src)
{
    src = deserialize_field(message.search_id, src);
    std::copy_n(src, 128, message.sender_public_key.begin());
    std::advance(src, 128);
    std::copy_n(src, 92, message.file_hash.begin());
    std::advance(src, 92);
    return src;
}

template<typename InputIt>
static InputIt deserialize_payload(OfferMessage & /*message*/, InputIt src)
{
    // TBI
    return src;
}

template<typename InputIt>
static InputIt deserialize_payload(UncacheMessage &message, InputIt src)
{
    std::copy_n(src, 92, message.file_hash.begin());
    std::advance(src, 92);
    return src;
}

template<typename InputIt>
static InputIt deserialize_payload(ConfirmTransferMessage &message, InputIt src)
{
    src = deserialize_field(message.offer_id, src);
    return src;
}

template<typename InputIt>
static InputIt deserialize_payload(RequestProxyMessage &message, InputIt src)
{
    src = deserialize_field(message.part_size, src);
    return src;
}

template<typename InputIt>
static InputIt deserialize_payload(InitUploadMessage &message, InputIt src)
{
    src = deserialize_field(message.offer_id, src);
    return src;
}

template<typename InputIt>
static InputIt deserialize_payload(UploadMessage &message, InputIt src)
{
    src = deserialize_field(message.offset, src);
    uint32_t data_size;
    src = deserialize_field(data_size, src);
    message.data.resize(data_size);
    std::copy_n(src, data_size, message.data.begin());
    std::advance(src, data_size);
    return src;
}

template<typename InputIt>
static InputIt deserialize_payload(FetchMessage &message, InputIt src)
{
    src = deserialize_field(message.offer_id, src);
    src = deserialize_field(message.drop_point, src);
    return src;
}

template<typename InputIt>
static InputIt deserialize_payload(InitDownloadMessage &message, InputIt src)
{
    src = deserialize_field(message.offer_id, src);
    return src;
}

template<typename InputIt>
static InputIt deserialize_payload(PullReply &message, InputIt src)
{
    uint8_t address_count;
    src = deserialize_field(address_count, src);
    message.peers.resize(address_count);
    for (auto &addr : message.peers)
    {
        src = deserialize_field(addr, src);
    }
    return src;
}
}  // namespace

std::vector<uint8_t> MessageSerializerImpl::serialize(const PullMessage &message) const
{
    std::vector<uint8_t> out(
        sizeof(message.request_code) + sizeof(message.request_id) + sizeof(message.address_count));

    auto dest = out.begin();
    dest      = serialize_field(message.request_code, dest);
    dest      = serialize_field(message.request_id, dest);
    serialize_field(message.address_count, dest);

    return out;
}

std::vector<uint8_t> MessageSerializerImpl::serialize(const PushMessage &message) const
{
    std::vector<uint8_t> out(sizeof(message.request_code) + sizeof(message.request_id));

    auto dest = out.begin();
    dest      = serialize_field(message.request_code, dest);
    serialize_field(message.request_id, dest);

    return out;
}

std::vector<uint8_t> MessageSerializerImpl::serialize(const ByeMessage &message) const
{
    std::vector<uint8_t> out(sizeof(message.request_code) + sizeof(message.request_id));

    auto dest = out.begin();
    dest      = serialize_field(message.request_code, dest);
    serialize_field(message.request_id, dest);

    return out;
}

std::vector<uint8_t> MessageSerializerImpl::serialize(const DeadMessage &message) const
{
    using ListSizeT = uint8_t;

    std::vector<uint8_t> out(sizeof(message.request_code) + sizeof(message.request_id) +
                             sizeof(ListSizeT) + message.nodes.size() * sizeof(message.nodes[0]));

    auto dest = out.begin();
    dest      = serialize_field(message.request_code, dest);
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
    std::vector<uint8_t> out(sizeof(message.request_code) + sizeof(message.request_id));

    auto dest = out.begin();
    dest      = serialize_field(message.request_code, dest);
    serialize_field(message.request_id, dest);

    return out;
}

std::vector<uint8_t> MessageSerializerImpl::serialize(const DNLSyncMessage &message) const
{
    using ListSizeT  = uint8_t;
    using TimestampT = uint64_t;

    size_t entry_size =
        sizeof(message.entries[0].address) + sizeof(message.entries[0].action) + sizeof(TimestampT);
    std::vector<uint8_t> out(sizeof(message.request_code) + sizeof(message.request_id) +
                             sizeof(ListSizeT) + message.entries.size() * entry_size);

    auto dest = out.begin();
    dest      = serialize_field(message.request_code, dest);
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
    std::vector<uint8_t> out(sizeof(message.request_code) + sizeof(message.request_id) +
                             sizeof(message.search_id) + sizeof(message.sender_public_key) +
                             sizeof(message.file_hash));

    auto dest = out.begin();
    dest      = serialize_field(message.request_code, dest);
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
        sizeof(message.request_code) + sizeof(message.request_id) + sizeof(message.file_hash));

    auto dest = out.begin();
    dest      = serialize_field(message.request_code, dest);
    dest      = serialize_field(message.request_id, dest);
    std::copy(message.file_hash.cbegin(), message.file_hash.cend(), dest);

    return out;
}

std::vector<uint8_t> MessageSerializerImpl::serialize(const ConfirmTransferMessage &message) const
{
    std::vector<uint8_t> out(
        sizeof(message.request_code) + sizeof(message.request_id) + sizeof(message.offer_id));

    auto dest = out.begin();
    dest      = serialize_field(message.request_code, dest);
    dest      = serialize_field(message.request_id, dest);
    serialize_field(message.offer_id, dest);

    return out;
}

std::vector<uint8_t> MessageSerializerImpl::serialize(const RequestProxyMessage &message) const
{
    std::vector<uint8_t> out(
        sizeof(message.request_code) + sizeof(message.request_id) + sizeof(message.part_size));

    auto dest = out.begin();
    dest      = serialize_field(message.request_code, dest);
    dest      = serialize_field(message.request_id, dest);
    serialize_field(message.part_size, dest);

    return out;
}

std::vector<uint8_t> MessageSerializerImpl::serialize(const InitUploadMessage &message) const
{
    std::vector<uint8_t> out(
        sizeof(message.request_code) + sizeof(message.request_id) + sizeof(message.offer_id));

    auto dest = out.begin();
    dest      = serialize_field(message.request_code, dest);
    dest      = serialize_field(message.request_id, dest);
    serialize_field(message.offer_id, dest);

    return out;
}

std::vector<uint8_t> MessageSerializerImpl::serialize(const UploadMessage &message) const
{
    std::vector<uint8_t> out(sizeof(message.request_code) + sizeof(message.request_id) +
                             sizeof(message.offset) + sizeof(PartSize) +
                             message.data.size() * sizeof(message.data[0]));

    auto dest = out.begin();
    dest      = serialize_field(message.request_code, dest);
    dest      = serialize_field(message.request_id, dest);
    dest      = serialize_field(message.offset, dest);
    dest      = serialize_field(PartSize(message.data.size()), dest);
    std::copy(message.data.cbegin(), message.data.cend(), dest);

    return out;
}

std::vector<uint8_t> MessageSerializerImpl::serialize(const FetchMessage &message) const
{
    std::vector<uint8_t> out(sizeof(message.request_code) + sizeof(message.request_id) +
                             sizeof(message.offer_id) + sizeof(message.drop_point));

    auto dest = out.begin();
    dest      = serialize_field(message.request_code, dest);
    dest      = serialize_field(message.request_id, dest);
    dest      = serialize_field(message.offer_id, dest);
    serialize_field(message.drop_point, dest);

    return out;
}

std::vector<uint8_t> MessageSerializerImpl::serialize(const InitDownloadMessage &message) const
{
    std::vector<uint8_t> out(
        sizeof(message.request_code) + sizeof(message.request_id) + sizeof(message.offer_id));

    auto dest = out.begin();
    dest      = serialize_field(message.request_code, dest);
    dest      = serialize_field(message.request_id, dest);
    serialize_field(message.offer_id, dest);

    return out;
}

std::vector<uint8_t> MessageSerializerImpl::serialize(const BasicReply &message) const
{
    std::vector<uint8_t> out(2 * sizeof(message.request_code) + sizeof(message.status_code) +
                             sizeof(message.request_id));

    auto dest = out.begin();
    dest      = serialize_field(message.request_code, dest);
    dest      = serialize_field(message.request_id, dest);
    dest      = serialize_field(message.status_code, dest);
    serialize_field(message.source_request_code, dest);

    return out;
}

std::vector<uint8_t> MessageSerializerImpl::serialize(const PullReply &message) const
{
    using ListSizeT = uint8_t;

    std::vector<uint8_t> out(2 * sizeof(message.request_code) + sizeof(message.status_code) +
                             sizeof(message.request_id) + sizeof(ListSizeT) +
                             message.peers.size() * sizeof(message.peers[0]));

    auto dest = out.begin();
    dest      = serialize_field(message.request_code, dest);
    dest      = serialize_field(message.request_id, dest);
    dest      = serialize_field(message.status_code, dest);
    dest      = serialize_field(message.source_request_code, dest);
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
    const std::vector<uint8_t> &bytes, RequestDeserializationResultReceptor &receptor) const
{
    auto src = bytes.cbegin();

    RequestCode request_code;
    src = deserialize_field(request_code, src);
    RequestId request_id;
    src = deserialize_field(request_id, src);

    switch (request_code)
    {
        case RequestCode::PULL:
        {
            PullMessage msg;
            msg.request_id = request_id;
            deserialize_payload(msg, src);
            receptor.deserialized(msg);
            break;
        }
        case RequestCode::PUSH:
        {
            PushMessage msg;
            msg.request_id = request_id;
            receptor.deserialized(msg);
            break;
        }
        case RequestCode::BYE:
        {
            ByeMessage msg;
            msg.request_id = request_id;
            receptor.deserialized(msg);
            break;
        }
        case RequestCode::DEAD:
        {
            DeadMessage msg;
            msg.request_id = request_id;
            deserialize_payload(msg, src);
            receptor.deserialized(msg);
            break;
        }
        case RequestCode::PING:
        {
            PingMessage msg;
            msg.request_id = request_id;
            receptor.deserialized(msg);
            break;
        }
        case RequestCode::DNLSYNC:
        {
            DNLSyncMessage msg;
            msg.request_id = request_id;
            deserialize_payload(msg, src);
            receptor.deserialized(msg);
            break;
        }
        case RequestCode::SEARCH:
        {
            SearchMessage msg;
            msg.request_id = request_id;
            deserialize_payload(msg, src);
            receptor.deserialized(msg);
            break;
        }
        case RequestCode::OFFER:
        {
            OfferMessage msg;
            msg.request_id = request_id;
            deserialize_payload(msg, src);
            receptor.deserialized(msg);
            break;
        }
        case RequestCode::UNCACHE:
        {
            UncacheMessage msg;
            msg.request_id = request_id;
            deserialize_payload(msg, src);
            receptor.deserialized(msg);
            break;
        }
        case RequestCode::CONFIRMTRANSFER:
        {
            ConfirmTransferMessage msg;
            msg.request_id = request_id;
            deserialize_payload(msg, src);
            receptor.deserialized(msg);
            break;
        }
        case RequestCode::REQUESTPROXY:
        {
            RequestProxyMessage msg;
            msg.request_id = request_id;
            deserialize_payload(msg, src);
            receptor.deserialized(msg);
            break;
        }
        case RequestCode::INITUPLOAD:
        {
            InitUploadMessage msg;
            msg.request_id = request_id;
            deserialize_payload(msg, src);
            receptor.deserialized(msg);
            break;
        }
        case RequestCode::UPLOAD:
        {
            UploadMessage msg;
            msg.request_id = request_id;
            deserialize_payload(msg, src);
            receptor.deserialized(msg);
            break;
        }
        case RequestCode::FETCH:
        {
            FetchMessage msg;
            msg.request_id = request_id;
            deserialize_payload(msg, src);
            receptor.deserialized(msg);
            break;
        }
        case RequestCode::INITDOWNLOAD:
        {
            InitDownloadMessage msg;
            msg.request_id = request_id;
            deserialize_payload(msg, src);
            receptor.deserialized(msg);
            break;
        }
        case RequestCode::REPLY:
        {
            StatusCode status_code;
            src = deserialize_field(status_code, src);
            RequestCode source_request_code;
            src = deserialize_field(source_request_code, src);

            switch (source_request_code)
            {
                case RequestCode::PULL:
                {
                    PullReply msg;
                    msg.request_id  = request_id;
                    msg.status_code = status_code;
                    deserialize_payload(msg, src);
                    receptor.deserialized(msg);
                    break;
                }
                default:
                {
                    BasicReply msg {source_request_code};
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
            LOG(ERROR) << "Invalid request code: " << int(request_code);
            receptor.error();
            break;
        }
    }
}
}  // namespace sand::protocol
