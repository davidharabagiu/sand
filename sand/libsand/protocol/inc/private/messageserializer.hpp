#ifndef SAND_PROTOCOL_MESSAGESERIALIZER_HPP_
#define SAND_PROTOCOL_MESSAGESERIALIZER_HPP_

#include <algorithm>
#include <any>
#include <chrono>
#include <cstdint>
#include <iterator>
#include <limits>
#include <type_traits>

#include "deserializationresultreceptor.hpp"
#include "messages.hpp"

namespace sand::protocol
{
class MessageSerializer
{
public:
    template<typename OutputIt>
    static OutputIt serialize(const PullMessage &message, OutputIt dest)
    {
        dest = serialize_field(uint8_t(MessageCode::PULL), dest);
        dest = serialize_field<uint8_t>(message.address_count, dest);
        return dest;
    }

    template<typename OutputIt>
    static OutputIt serialize(const PushMessage &message, OutputIt dest)
    {
        dest = serialize_field(uint8_t(MessageCode::PUSH), dest);
        return dest;
    }

    template<typename OutputIt>
    static OutputIt serialize(const ByeMessage &message, OutputIt dest)
    {
        dest = serialize_field(uint8_t(MessageCode::BYE), dest);
        return dest;
    }

    template<typename OutputIt>
    static OutputIt serialize(const DeadMessage &message, OutputIt dest)
    {
        dest = serialize_field(uint8_t(MessageCode::DEAD), dest);
        dest = serialize_field<uint8_t>(
            std::min(std::numeric_limits<uint8_t>::max(), message.nodes.size()), dest);
        for (Address a : message.nodes)
        {
            dest = serialize_field<uint32_t>(a, dest);
        }
        return dest;
    }

    template<typename OutputIt>
    static OutputIt serialize(const PingMessage &message, OutputIt dest)
    {
        dest = serialize_field(uint8_t(MessageCode::PING), dest);
        return dest;
    }

    template<typename OutputIt>
    static OutputIt serialize(const DNLSyncMessage &message, OutputIt dest)
    {
        dest = serialize_field(uint8_t(MessageCode::DNLSYNC), dest);
        dest = serialize_field<uint8_t>(
            std::min(std::numeric_limits<uint8_t>::max(), message.entries.size()), dest);
        for (const auto &entry : message.entries)
        {
            dest = serialize_field<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                entry.timestamp.time_since_epoch())
                                                 .count());
            dest = serialize_field<uint32_t>(entry.address, dest);
            dest = serialize_field<uint8_t>(entry.action, dest);
        }
        return dest;
    }

    template<typename OutputIt>
    static OutputIt serialize(const SearchMessage &message, OutputIt dest)
    {
        dest = serialize_field(uint8_t(MessageCode::SEARCH), dest);
        dest = serialize_field<uint64_t>(message.search_id, dest);
        dest =
            std::copy(message.sender_public_key.cbegin(), message.sender_public_key.cend(), dest);
        dest = std::copy(message.file_hash.cbegin(), message.file_hash.cend(), dest);
        return dest;
    }

    template<typename OutputIt>
    static OutputIt serialize(const OfferMessage &message, OutputIt dest)
    {
        // TBI
    }

    template<typename OutputIt>
    static OutputIt serialize(const UncacheMessage &message, OutputIt dest)
    {
        dest = serialize_field(uint8_t(MessageCode::UNCACHE), dest);
        dest = std::copy(message.file_hash.cbegin(), message.file_hash.cend(), dest);
        return dest;
    }

    template<typename OutputIt>
    static OutputIt serialize(const ConfirmTransferMessage &message, OutputIt dest)
    {
        dest = serialize_field(uint8_t(MessageCode::CONFIRMTRANSFER), dest);
        dest = serialize_field<uint64_t>(message.offer_id, dest);
        return dest;
    }

    template<typename OutputIt>
    static OutputIt serialize(const RequestProxyMessage &message, OutputIt dest)
    {
        dest = serialize_field(uint8_t(MessageCode::REQUESTPROXY), dest);
        dest = serialize_field<uint32_t>(message.part_size, dest);
        return dest;
    }

    template<typename OutputIt>
    static OutputIt serialize(const InitUploadMessage &message, OutputIt dest)
    {
        dest = serialize_field(uint8_t(MessageCode::INITUPLOAD), dest);
        dest = serialize_field<uint64_t>(message.offer_id, dest);
        return dest;
    }

    template<typename OutputIt>
    static OutputIt serialize(const UploadMessage &message, OutputIt dest)
    {
        dest = serialize_field(uint8_t(MessageCode::UPLOAD), dest);
        dest = serialize_field<uint32_t>(message.offset, dest);
        dest = serialize_field<uint32_t>(
            std::min(std::numeric_limits<uint32_t>::max(), message.data.size()), dest);
        dest = std::copy(message.data.cbegin(), message.data.cend(), dest);
        return dest;
    }

    template<typename OutputIt>
    static OutputIt serialize(const FetchMessage &message, OutputIt dest)
    {
        dest = serialize_field(uint8_t(MessageCode::FETCH), dest);
        dest = serialize_field<uint64_t>(message.offer_id, dest);
        dest = serialize_field<uint32_t>(message.drop_point, dest);
        return dest;
    }

    template<typename OutputIt>
    static OutputIt serialize(const InitDownloadMessage &message, OutputIt dest)
    {
        dest = serialize_field(uint8_t(MessageCode::INITDOWNLOAD), dest);
        dest = serialize_field<uint64_t>(message.offer_id, dest);
        return dest;
    }

    template<typename InputIt>
    static InputIt deserialize(InputIt src, DeserializationResultReceptor &receptor)
    {
        MessageCode msg_code;
        src = deserialize_field(msg_code, src, 1);
        switch (msg_code)
        {
            case MessageCode::PULL:
            {
                PullMessage msg;
                src = deserialize(msg, src);
                receptor.deserialized(msg);
                break;
            }
            case MessageCode::PUSH:
            {
                PushMessage msg;
                receptor.deserialized(msg);
                break;
            }
            case MessageCode::BYE:
            {
                ByeMessage msg;
                receptor.deserialized(msg);
                break;
            }
            case MessageCode::DEAD:
            {
                DeadMessage msg;
                src = deserialize(msg, src);
                receptor.deserialized(msg);
                break;
            }
            case MessageCode::PING:
            {
                PingMessage msg;
                receptor.deserialized(msg);
                break;
            }
            case MessageCode::DNLSYNC:
            {
                DNLSyncMessage msg;
                src = deserialize(msg, src);
                receptor.deserialized(msg);
                break;
            }
            case MessageCode::SEARCH:
            {
                SearchMessage msg;
                src = deserialize(msg, src);
                receptor.deserialized(msg);
                break;
            }
            case MessageCode::OFFER:
            {
                OfferMessage msg;
                src = deserialize(msg, src);
                receptor.deserialized(msg);
                break;
            }
            case MessageCode::UNCACHE:
            {
                UncacheMessage msg;
                src = deserialize(msg, src);
                receptor.deserialized(msg);
                break;
            }
            case MessageCode::CONFIRMTRANSFER:
            {
                ConfirmTransferMessage msg;
                src = deserialize(msg, src);
                receptor.deserialized(msg);
                break;
            }
            case MessageCode::REQUESTPROXY:
            {
                RequestProxyMessage msg;
                src = deserialize(msg, src);
                receptor.deserialized(msg);
                break;
            }
            case MessageCode::INITUPLOAD:
            {
                InitUploadMessage msg;
                src = deserialize(msg, src);
                receptor.deserialized(msg);
                break;
            }
            case MessageCode::UPLOAD:
            {
                UploadMessage msg;
                src = deserialize(msg, src);
                receptor.deserialized(msg);
                break;
            }
            case MessageCode::FETCH:
            {
                FetchMessage msg;
                src = deserialize(msg, src);
                receptor.deserialized(msg);
                break;
            }
            case MessageCode::INITDOWNLOAD:
            {
                InitDownloadMessage msg;
                src = deserialize(msg, src);
                receptor.deserialized(msg);
                break;
            }
            default:
            {
                receptor.error();
                break;
            }
        }
        return src;
    }

private:
    enum class MessageCode : uint8_t
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
    static auto deserialize_field(T &field, InputIt src_begin, size_t src_count)
        -> std::enable_if_t<std::is_pod_v<T>, InputIt>
    {
        auto dest = reinterpret_cast<uint8_t *>(&field);
#ifdef IS_BIG_ENDIAN
        std::copy_n(std::make_reverse_iterator(src_begin), src_count, dest);
#else
        std::copy_n(src_begin, src_count, dest);
#endif  // IS_BIG_ENDIAN
        std::advance(src_begin, src_count);
        return src_begin;
    }

    template<typename InputIt>
    static InputIt deserialize(PullMessage &message, InputIt src)
    {
        src = deserialize_field(message.address_count, src, 1);
        return src;
    }

    template<typename InputIt>
    static InputIt deserialize(DeadMessage &message, InputIt src)
    {
        uint8_t address_count;
        src = deserialize_field(address_count, src, 1);
        message.nodes.resize(address_count);
        for (Address &addr : message.nodes)
        {
            src = deserialize_field<uint32_t>(addr, src, 4);
        }
        return src;
    }

    template<typename InputIt>
    static InputIt deserialize(DNLSyncMessage &message, InputIt src)
    {
        uint8_t entry_count;
        src = deserialize_field(entry_count, src, 1);
        message.entries.resize(entry_count);
        for (auto &entry : message.entries)
        {
            uint64_t ts;
            src = deserialize_field(ts, src, 8);
            src = deserialize_field(entry.address, src, 4);
            src = deserialize_field(entry.action, src, 1);

            entry.timestamp = std::chrono::milliseconds(ts);
        }
        return src;
    }

    template<typename InputIt>
    static InputIt deserialize(SearchMessage &message, InputIt src)
    {
        src = deserialize_field(message.search_id, src, 8);
        std::copy_n(src, 128, message.sender_public_key.begin());
        std::advance(src, 128);
        std::copy_n(src, 92, message.file_hash);
        std::advance(src, 92);
        return src;
    }

    template<typename InputIt>
    static InputIt deserialize(OfferMessage &message, InputIt src)
    {
        // TBI
    }

    template<typename InputIt>
    static InputIt deserialize(UncacheMessage &message, InputIt src)
    {
        std::copy_n(src, 92, message.file_hash);
        std::advance(src, 92);
        return src;
    }

    template<typename InputIt>
    static InputIt deserialize(ConfirmTransferMessage &message, InputIt src)
    {
        src = deserialize_field(message.offer_id, src, 8);
        return src;
    }

    template<typename InputIt>
    static InputIt deserialize(RequestProxyMessage &message, InputIt src)
    {
        src = deserialize_field(message.part_size, src, 4);
        return src;
    }

    template<typename InputIt>
    static InputIt deserialize(InitUploadMessage &message, InputIt src)
    {
        src = deserialize_field(message.offer_id, src, 8);
        return src;
    }

    template<typename InputIt>
    static InputIt deserialize(UploadMessage &message, InputIt src)
    {
        src = deserialize_field(message.offset, src, 4);
        uint32_t data_size;
        src = deserialize_field(data_size, src, 4);
        message.data.resize(data_size);
        std::copy_n(src, data_size, message.data.begin());
        std::advance(src, data_size);
        return src;
    }

    template<typename InputIt>
    static InputIt deserialize(FetchMessage &message, InputIt src)
    {
        src = deserialize_field(message.offer_id, src, 8);
        src = deserialize_field(message.drop_point, src, 4);
        return src;
    }

    template<typename InputIt>
    static InputIt deserialize(InitDownloadMessage &message, InputIt src)
    {
        src = deserialize_field(message.offer_id, src, 8);
        return src;
    }
};

}  // namespace sand::protocol

#endif  // SAND_PROTOCOL_MESSAGESERIALIZER_HPP_
