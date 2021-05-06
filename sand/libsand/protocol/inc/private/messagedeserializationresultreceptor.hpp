#ifndef SAND_PROTOCOL_MESSAGEDESERIALIZATIONRESULTRECEPTOR_HPP_
#define SAND_PROTOCOL_MESSAGEDESERIALIZATIONRESULTRECEPTOR_HPP_

#include "messages_decl.hpp"

namespace sand::protocol
{
class MessageDeserializationResultReceptor
{
public:
    virtual ~MessageDeserializationResultReceptor() = default;

    virtual void deserialized(const PullMessage &message)            = 0;
    virtual void deserialized(const PushMessage &message)            = 0;
    virtual void deserialized(const ByeMessage &message)             = 0;
    virtual void deserialized(const DeadMessage &message)            = 0;
    virtual void deserialized(const PingMessage &message)            = 0;
    virtual void deserialized(const DNLSyncMessage &message)         = 0;
    virtual void deserialized(const SearchMessage &message)          = 0;
    virtual void deserialized(const OfferMessage &message)           = 0;
    virtual void deserialized(const UncacheMessage &message)         = 0;
    virtual void deserialized(const ConfirmTransferMessage &message) = 0;
    virtual void deserialized(const RequestProxyMessage &message)    = 0;
    virtual void deserialized(const InitUploadMessage &message)      = 0;
    virtual void deserialized(const UploadMessage &message)          = 0;
    virtual void deserialized(const FetchMessage &message)           = 0;
    virtual void deserialized(const InitDownloadMessage &message)    = 0;
    virtual void deserialized(const BasicReply &message)             = 0;
    virtual void deserialized(const PullReply &message)              = 0;
    virtual void error()                                             = 0;
};
}  // namespace sand::protocol

#endif  // SAND_PROTOCOL_MESSAGEDESERIALIZATIONRESULTRECEPTOR_HPP_
