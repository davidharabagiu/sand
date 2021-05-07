#include "messageserializerimpl.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <limits>
#include <utility>

#include <glog/logging.h>

#include "messagedeserializationresultreceptor.hpp"
#include "messages.hpp"
#include "rsacipher.hpp"
#include "serializationutils.hpp"

namespace sand::protocol
{
namespace
{
template<typename InputIt>
InputIt deserialize_payload(PullMessage &message, InputIt src_begin, InputIt src_end, bool &ok)
{
    ok        = true;
    src_begin = serialization::deserialize_field(message.address_count, src_begin, src_end, ok);
    return src_begin;
}

template<typename InputIt>
InputIt deserialize_payload(DeadMessage &message, InputIt src_begin, InputIt src_end, bool &ok)
{
    ok = true;
    uint8_t address_count;
    src_begin = serialization::deserialize_field(address_count, src_begin, src_end, ok);
    if (!ok)
    {
        return src_begin;
    }
    message.nodes.resize(address_count);
    for (auto &addr : message.nodes)
    {
        src_begin = serialization::deserialize_field(addr, src_begin, src_end, ok);
        if (!ok)
        {
            return src_begin;
        }
    }
    return src_begin;
}

template<typename InputIt>
InputIt deserialize_payload(DNLSyncMessage &message, InputIt src_begin, InputIt src_end, bool &ok)
{
    ok = true;
    uint8_t entry_count;
    src_begin = serialization::deserialize_field(entry_count, src_begin, src_end, ok);
    if (!ok)
    {
        return src_begin;
    }
    message.entries.resize(entry_count);
    for (auto &entry : message.entries)
    {
        uint64_t ts;

        src_begin = serialization::deserialize_field(ts, src_begin, src_end, ok);
        if (!ok)
        {
            return src_begin;
        }

        src_begin = serialization::deserialize_field(entry.address, src_begin, src_end, ok);
        if (!ok)
        {
            return src_begin;
        }

        src_begin = serialization::deserialize_field(entry.action, src_begin, src_end, ok);
        if (!ok)
        {
            return src_begin;
        }

        entry.timestamp = Timestamp(std::chrono::milliseconds(ts));
    }
    return src_begin;
}

template<typename InputIt>
InputIt deserialize_payload(SearchMessage &message, InputIt src_begin, InputIt src_end, bool &ok)
{
    ok        = true;
    src_begin = serialization::deserialize_field(message.search_id, src_begin, src_end, ok);
    if (!ok)
    {
        return src_begin;
    }

    uint16_t pub_key_size;
    src_begin = serialization::deserialize_field(pub_key_size, src_begin, src_end, ok);
    if (!ok)
    {
        return src_begin;
    }

    if (!serialization::check_distance(src_begin, pub_key_size, src_end))
    {
        ok = false;
        return src_begin;
    }
    message.sender_public_key.resize(pub_key_size);
    std::copy_n(src_begin, pub_key_size, message.sender_public_key.begin());
    std::advance(src_begin, pub_key_size);

    if (!serialization::check_distance(src_begin, 92, src_end))
    {
        ok = false;
        return src_begin;
    }
    std::copy_n(src_begin, 92, message.file_hash.begin());
    std::advance(src_begin, 92);

    return src_begin;
}

template<typename InputIt>
InputIt deserialize_payload(OfferMessage &message, InputIt src_begin, InputIt src_end, bool &ok)
{
    ok = true;

    src_begin = serialization::deserialize_field(message.search_id, src_begin, src_end, ok);
    if (!ok)
    {
        return src_begin;
    }
    src_begin = serialization::deserialize_field(message.offer_id, src_begin, src_end, ok);
    if (!ok)
    {
        return src_begin;
    }

    uint16_t encrypted_data_size;
    src_begin = serialization::deserialize_field(encrypted_data_size, src_begin, src_end, ok);
    if (!ok)
    {
        return src_begin;
    }

    if (!serialization::check_distance(src_begin, encrypted_data_size, src_end))
    {
        ok = false;
        return src_begin;
    }
    message.encrypted_data.resize(encrypted_data_size);
    std::copy_n(src_begin, encrypted_data_size, message.encrypted_data.begin());
    std::advance(src_begin, encrypted_data_size);

    return src_begin;
}

template<typename InputIt>
InputIt deserialize_payload(UncacheMessage &message, InputIt src_begin, InputIt src_end, bool &ok)
{
    ok = true;

    if (!serialization::check_distance(src_begin, 92, src_end))
    {
        ok = false;
        return src_begin;
    }
    std::copy_n(src_begin, 92, message.file_hash.begin());
    std::advance(src_begin, 92);

    return src_begin;
}

template<typename InputIt>
InputIt deserialize_payload(
    ConfirmTransferMessage &message, InputIt src_begin, InputIt src_end, bool &ok)
{
    ok        = true;
    src_begin = serialization::deserialize_field(message.offer_id, src_begin, src_end, ok);
    return src_begin;
}

template<typename InputIt>
InputIt deserialize_payload(
    RequestProxyMessage &message, InputIt src_begin, InputIt src_end, bool &ok)
{
    ok        = true;
    src_begin = serialization::deserialize_field(message.part_size, src_begin, src_end, ok);
    return src_begin;
}

template<typename InputIt>
InputIt deserialize_payload(
    InitUploadMessage &message, InputIt src_begin, InputIt src_end, bool &ok)
{
    ok        = true;
    src_begin = serialization::deserialize_field(message.offer_id, src_begin, src_end, ok);
    return src_begin;
}

template<typename InputIt>
InputIt deserialize_payload(UploadMessage &message, InputIt src_begin, InputIt src_end, bool &ok)
{
    ok = true;

    src_begin = serialization::deserialize_field(message.offset, src_begin, src_end, ok);
    if (!ok)
    {
        return src_begin;
    }

    uint32_t data_size;
    src_begin = serialization::deserialize_field(data_size, src_begin, src_end, ok);
    if (!ok)
    {
        return src_begin;
    }

    if (!serialization::check_distance(src_begin, data_size, src_end))
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
InputIt deserialize_payload(FetchMessage &message, InputIt src_begin, InputIt src_end, bool &ok)
{
    ok = true;

    src_begin = serialization::deserialize_field(message.offer_id, src_begin, src_end, ok);
    if (!ok)
    {
        return src_begin;
    }
    src_begin = serialization::deserialize_field(message.drop_point, src_begin, src_end, ok);

    return src_begin;
}

template<typename InputIt>
InputIt deserialize_payload(
    InitDownloadMessage &message, InputIt src_begin, InputIt src_end, bool &ok)
{
    ok        = true;
    src_begin = serialization::deserialize_field(message.offer_id, src_begin, src_end, ok);
    return src_begin;
}

template<typename InputIt>
InputIt deserialize_payload(PullReply &message, InputIt src_begin, InputIt src_end, bool &ok)
{
    ok = true;

    uint8_t address_count;
    src_begin = serialization::deserialize_field(address_count, src_begin, src_end, ok);
    if (!ok)
    {
        return src_begin;
    }
    message.peers.resize(address_count);
    for (auto &addr : message.peers)
    {
        src_begin = serialization::deserialize_field(addr, src_begin, src_end, ok);
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
    dest      = serialization::serialize_field(message.message_code, dest);
    dest      = serialization::serialize_field(message.request_id, dest);
    serialization::serialize_field(message.address_count, dest);

    return out;
}

std::vector<uint8_t> MessageSerializerImpl::serialize(const PushMessage &message) const
{
    std::vector<uint8_t> out(sizeof(message.message_code) + sizeof(message.request_id));

    auto dest = out.begin();
    dest      = serialization::serialize_field(message.message_code, dest);
    serialization::serialize_field(message.request_id, dest);

    return out;
}

std::vector<uint8_t> MessageSerializerImpl::serialize(const ByeMessage &message) const
{
    std::vector<uint8_t> out(sizeof(message.message_code) + sizeof(message.request_id));

    auto dest = out.begin();
    dest      = serialization::serialize_field(message.message_code, dest);
    serialization::serialize_field(message.request_id, dest);

    return out;
}

std::vector<uint8_t> MessageSerializerImpl::serialize(const DeadMessage &message) const
{
    using ListSizeT = uint8_t;

    std::vector<uint8_t> out(sizeof(message.message_code) + sizeof(message.request_id) +
                             sizeof(ListSizeT) + message.nodes.size() * sizeof(message.nodes[0]));

    auto dest = out.begin();
    dest      = serialization::serialize_field(message.message_code, dest);
    dest      = serialization::serialize_field(message.request_id, dest);
    dest      = serialization::serialize_field(
        ListSizeT(std::min(size_t(std::numeric_limits<ListSizeT>::max()), message.nodes.size())),
        dest);
    for (auto addr : message.nodes)
    {
        dest = serialization::serialize_field(addr, dest);
    }

    return out;
}

std::vector<uint8_t> MessageSerializerImpl::serialize(const PingMessage &message) const
{
    std::vector<uint8_t> out(sizeof(message.message_code) + sizeof(message.request_id));

    auto dest = out.begin();
    dest      = serialization::serialize_field(message.message_code, dest);
    serialization::serialize_field(message.request_id, dest);

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
    dest      = serialization::serialize_field(message.message_code, dest);
    dest      = serialization::serialize_field(message.request_id, dest);
    dest      = serialization::serialize_field(
        ListSizeT(std::min(size_t(std::numeric_limits<ListSizeT>::max()), message.entries.size())),
        dest);
    for (auto entry : message.entries)
    {
        dest = serialization::serialize_field(
            TimestampT(std::chrono::duration_cast<std::chrono::milliseconds>(
                entry.timestamp.time_since_epoch())
                           .count()),
            dest);
        dest = serialization::serialize_field(entry.address, dest);
        dest = serialization::serialize_field(entry.action, dest);
    }

    return out;
}

std::vector<uint8_t> MessageSerializerImpl::serialize(const SearchMessage &message) const
{
    using PubKeyLenT = uint16_t;

    const auto max_key_size = std::numeric_limits<PubKeyLenT>::max();
    if (message.sender_public_key.size() > max_key_size)
    {
        LOG(ERROR) << "Size of Search message public key exceeds the maximum allowed ("
                   << message.sender_public_key.size() << " > " << max_key_size << ")";
        return {};
    }

    std::vector<uint8_t> out(sizeof(message.message_code) + sizeof(message.request_id) +
                             sizeof(message.search_id) + sizeof(PubKeyLenT) +
                             message.sender_public_key.size() + sizeof(message.file_hash));

    auto dest = out.begin();
    dest      = serialization::serialize_field(message.message_code, dest);
    dest      = serialization::serialize_field(message.request_id, dest);
    dest      = serialization::serialize_field(message.search_id, dest);
    dest      = serialization::serialize_field(PubKeyLenT(message.sender_public_key.size()), dest);
    dest = std::copy(message.sender_public_key.cbegin(), message.sender_public_key.cend(), dest);
    std::copy(message.file_hash.cbegin(), message.file_hash.cend(), dest);

    return out;
}

std::vector<uint8_t> MessageSerializerImpl::serialize(const OfferMessage &message) const
{
    using EncryptedDataSizeT = uint16_t;

    const auto max_encrypted_data_size = std::numeric_limits<EncryptedDataSizeT>::max();
    if (message.encrypted_data.size() > max_encrypted_data_size)
    {
        LOG(ERROR) << "Size of Offer message encrypted data exceeds the maximum allowed ("
                   << message.encrypted_data.size() << " > " << max_encrypted_data_size << ")";
        return {};
    }

    std::vector<uint8_t> out(sizeof(message.message_code) + sizeof(message.request_id) +
                             sizeof(message.search_id) + sizeof(message.offer_id) +
                             sizeof(EncryptedDataSizeT) + message.encrypted_data.size());

    auto dest = out.begin();
    dest      = serialization::serialize_field(message.message_code, dest);
    dest      = serialization::serialize_field(message.request_id, dest);
    dest      = serialization::serialize_field(message.search_id, dest);
    dest      = serialization::serialize_field(message.offer_id, dest);
    dest = serialization::serialize_field(EncryptedDataSizeT(message.encrypted_data.size()), dest);
    std::copy(message.encrypted_data.cbegin(), message.encrypted_data.cend(), dest);

    return out;
}

std::vector<uint8_t> MessageSerializerImpl::serialize(const UncacheMessage &message) const
{
    std::vector<uint8_t> out(
        sizeof(message.message_code) + sizeof(message.request_id) + sizeof(message.file_hash));

    auto dest = out.begin();
    dest      = serialization::serialize_field(message.message_code, dest);
    dest      = serialization::serialize_field(message.request_id, dest);
    std::copy(message.file_hash.cbegin(), message.file_hash.cend(), dest);

    return out;
}

std::vector<uint8_t> MessageSerializerImpl::serialize(const ConfirmTransferMessage &message) const
{
    std::vector<uint8_t> out(
        sizeof(message.message_code) + sizeof(message.request_id) + sizeof(message.offer_id));

    auto dest = out.begin();
    dest      = serialization::serialize_field(message.message_code, dest);
    dest      = serialization::serialize_field(message.request_id, dest);
    serialization::serialize_field(message.offer_id, dest);

    return out;
}

std::vector<uint8_t> MessageSerializerImpl::serialize(const RequestProxyMessage &message) const
{
    std::vector<uint8_t> out(
        sizeof(message.message_code) + sizeof(message.request_id) + sizeof(message.part_size));

    auto dest = out.begin();
    dest      = serialization::serialize_field(message.message_code, dest);
    dest      = serialization::serialize_field(message.request_id, dest);
    serialization::serialize_field(message.part_size, dest);

    return out;
}

std::vector<uint8_t> MessageSerializerImpl::serialize(const InitUploadMessage &message) const
{
    std::vector<uint8_t> out(
        sizeof(message.message_code) + sizeof(message.request_id) + sizeof(message.offer_id));

    auto dest = out.begin();
    dest      = serialization::serialize_field(message.message_code, dest);
    dest      = serialization::serialize_field(message.request_id, dest);
    serialization::serialize_field(message.offer_id, dest);

    return out;
}

std::vector<uint8_t> MessageSerializerImpl::serialize(const UploadMessage &message) const
{
    const auto max_part_size = std::numeric_limits<PartSize>::max();
    if (message.data.size() > max_part_size)
    {
        LOG(ERROR) << "Size of Upload message data exceeds the maximum size of a file part ("
                   << message.data.size() << " > " << max_part_size << ")";
        return {};
    }

    std::vector<uint8_t> out(sizeof(message.message_code) + sizeof(message.request_id) +
                             sizeof(message.offset) + sizeof(PartSize) +
                             message.data.size() * sizeof(message.data[0]));

    auto dest = out.begin();
    dest      = serialization::serialize_field(message.message_code, dest);
    dest      = serialization::serialize_field(message.request_id, dest);
    dest      = serialization::serialize_field(message.offset, dest);
    dest      = serialization::serialize_field(PartSize(message.data.size()), dest);
    std::copy(message.data.cbegin(), message.data.cend(), dest);

    return out;
}

std::vector<uint8_t> MessageSerializerImpl::serialize(const FetchMessage &message) const
{
    std::vector<uint8_t> out(sizeof(message.message_code) + sizeof(message.request_id) +
                             sizeof(message.offer_id) + sizeof(message.drop_point));

    auto dest = out.begin();
    dest      = serialization::serialize_field(message.message_code, dest);
    dest      = serialization::serialize_field(message.request_id, dest);
    dest      = serialization::serialize_field(message.offer_id, dest);
    serialization::serialize_field(message.drop_point, dest);

    return out;
}

std::vector<uint8_t> MessageSerializerImpl::serialize(const InitDownloadMessage &message) const
{
    std::vector<uint8_t> out(
        sizeof(message.message_code) + sizeof(message.request_id) + sizeof(message.offer_id));

    auto dest = out.begin();
    dest      = serialization::serialize_field(message.message_code, dest);
    dest      = serialization::serialize_field(message.request_id, dest);
    serialization::serialize_field(message.offer_id, dest);

    return out;
}

std::vector<uint8_t> MessageSerializerImpl::serialize(const BasicReply &message) const
{
    std::vector<uint8_t> out(2 * sizeof(message.message_code) + sizeof(message.status_code) +
                             sizeof(message.request_id));

    auto dest = out.begin();
    dest      = serialization::serialize_field(message.message_code, dest);
    dest      = serialization::serialize_field(message.request_id, dest);
    dest      = serialization::serialize_field(message.status_code, dest);
    serialization::serialize_field(message.request_message_code, dest);

    return out;
}

std::vector<uint8_t> MessageSerializerImpl::serialize(const PullReply &message) const
{
    using ListSizeT = uint8_t;

    std::vector<uint8_t> out(2 * sizeof(message.message_code) + sizeof(message.status_code) +
                             sizeof(message.request_id) + sizeof(ListSizeT) +
                             message.peers.size() * sizeof(message.peers[0]));

    auto dest = out.begin();
    dest      = serialization::serialize_field(message.message_code, dest);
    dest      = serialization::serialize_field(message.request_id, dest);
    dest      = serialization::serialize_field(message.status_code, dest);
    dest      = serialization::serialize_field(message.request_message_code, dest);
    dest      = serialization::serialize_field(
        ListSizeT(std::min(size_t(std::numeric_limits<ListSizeT>::max()), message.peers.size())),
        dest);
    for (auto addr : message.peers)
    {
        dest = serialization::serialize_field(addr, dest);
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
    src_begin = serialization::deserialize_field(message_code, src_begin, src_end, ok);
    if (!ok)
    {
        receptor.error();
        return;
    }

    RequestId request_id;
    src_begin = serialization::deserialize_field(request_id, src_begin, src_end, ok);
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
            src_begin = serialization::deserialize_field(status_code, src_begin, src_end, ok);
            if (!ok)
            {
                receptor.error();
                return;
            }

            MessageCode request_message_code;
            src_begin =
                serialization::deserialize_field(request_message_code, src_begin, src_end, ok);
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
