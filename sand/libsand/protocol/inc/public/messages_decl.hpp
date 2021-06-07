#ifndef SAND_PROTOCOL_MESSAGES_DECL_HPP_
#define SAND_PROTOCOL_MESSAGES_DECL_HPP_

namespace sand::protocol
{
struct Message;
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
struct RequestDropPointMessage;
struct RequestLiftProxyMessage;
struct InitUploadMessage;
struct UploadMessage;
struct FetchMessage;
struct InitDownloadMessage;
struct BasicReply;
struct PullReply;
}  // namespace sand::protocol

#endif  // SAND_PROTOCOL_MESSAGES_DECL_HPP_
