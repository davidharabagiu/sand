#ifndef SAND_PROTOCOL_REQUESTDESERIALIZATIONRESULTRECEPTOR_HPP_
#define SAND_PROTOCOL_REQUESTDESERIALIZATIONRESULTRECEPTOR_HPP_

namespace sand::protocol
{
// Forward declarations
struct PullMessage;
struct PushMessage;
struct ByeMessage;
struct DeadMessage;
struct PingMessage;
struct DNLSyncMessage;
struct SearchMessage;
struct OfferMessage;
struct UncacheMessage;
struct ConfirmTransferMessage;
struct RequestProxyMessage;
struct InitUploadMessage;
struct UploadMessage;
struct FetchMessage;
struct InitDownloadMessage;

class RequestDeserializationResultReceptor
{
public:
    virtual ~RequestDeserializationResultReceptor() = default;

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
    virtual void error()                                             = 0;
};
}  // namespace sand::protocol

#endif  // SAND_PROTOCOL_REQUESTDESERIALIZATIONRESULTRECEPTOR_HPP_
