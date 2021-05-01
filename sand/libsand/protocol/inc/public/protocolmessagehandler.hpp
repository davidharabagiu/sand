#ifndef SAND_PROTOCOL_PROTOCOLMESSAGEHANDLER_HPP_
#define SAND_PROTOCOL_PROTOCOLMESSAGEHANDLER_HPP_

#include <future>
#include <memory>
#include <vector>

#include "address.hpp"
#include "messagefieldtypes.hpp"
#include "protocolmessagelistener.hpp"
#include "requesthandle.hpp"

namespace sand::protocol
{
class ProtocolMessageHandler
{
public:
    virtual ~Protocol() = default;

    virtual bool
    register_message_listener(const std::shared_ptr<ProtocolMessageListener> &listener) = 0;
    virtual bool
    unregister_message_listener(const std::shared_ptr<ProtocolMessageListener> &listener) = 0;

    virtual std::future<Reply<PullReplyPayload>> send_pull(Address       destination,
                                                           uint_least8_t address_count)       = 0;
    virtual std::future<BasicReply>              send_push(Address destination)               = 0;
    virtual bool                                 send_bye(Address destination)                = 0;
    virtual std::future<BasicReply>              send_dead(Address                     destination,
                                                           const std::vector<Address> &nodes) = 0;
    virtual std::future<BasicReply>              send_ping(Address destination)               = 0;
    virtual std::future<BasicReply>              send_dnl_sync(Address                          destination,
                                                               const std::vector<DNLSyncEntry> &entries) = 0;

    virtual std::future<BasicReply> send_search(Address destination, SearchId search_id,
                                                const NodePublicKey &my_public_key,
                                                const AHash &        ahash)                       = 0;
    virtual std::future<BasicReply> send_offer(Address destination, SearchId search_id,
                                               OfferId                      offer_id,
                                               const NodePublicKey &        destination_public_key,
                                               const TransferKey &          transfer_key,
                                               const std::vector<PartData> &parts)        = 0;
    virtual std::future<BasicReply> send_uncache(Address destination, const AHash &ahash) = 0;
    virtual std::future<BasicReply> send_confirm_transfer(Address destination,
                                                          OfferId offer_id)               = 0;

    virtual std::future<BasicReply> send_request_proxy(Address destination, PartSize part_size) = 0;
    virtual std::future<BasicReply> send_init_upload(Address destination, OfferId offer_id)     = 0;
    virtual std::future<BasicReply> send_upload(Address destination, PartSize offset,
                                                const std::vector<Byte> &data)                  = 0;
    virtual std::future<BasicReply> send_fetch(Address destination, OfferId offer_id,
                                               Address drop_point)                              = 0;
    virtual std::future<BasicReply> send_init_download(Address destination, OfferId offer_id)   = 0;
};
}  // namespace sand::protocol

#endif  // SAND_PROTOCOL_PROTOCOLMESSAGEHANDLER_HPP_
