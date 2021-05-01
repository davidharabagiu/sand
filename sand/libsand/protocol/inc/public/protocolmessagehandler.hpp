#ifndef SAND_PROTOCOL_PROTOCOLMESSAGEHANDLER_HPP_
#define SAND_PROTOCOL_PROTOCOLMESSAGEHANDLER_HPP_

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
    using RequestHandlePtr = std::unique_ptr<RequestHandle>;

    virtual ~Protocol() = default;

    virtual bool
    RegisterMessageListener(const std::shared_ptr<ProtocolMessageListener> &listener) = 0;
    virtual bool
    UnregisterMessageListener(const std::shared_ptr<ProtocolMessageListener> &listener) = 0;

    virtual RequestHandlePtr SendPull(Address destination, uint_least8_t address_count)       = 0;
    virtual RequestHandlePtr SendPush(Address destination)                                    = 0;
    virtual bool             SendBye(Address destination)                                     = 0;
    virtual RequestHandlePtr SendDead(Address destination, const std::vector<Address> &nodes) = 0;
    virtual RequestHandlePtr SendPing(Address destination)                                    = 0;
    virtual RequestHandlePtr SendDNLSync(Address                          destination,
                                         const std::vector<DNLSyncEntry> &entries)            = 0;

    virtual RequestHandlePtr SendSearch(Address destination, SearchId search_id,
                                        const NodePublicKey &my_public_key, const AHash &ahash) = 0;
    virtual RequestHandlePtr SendOffer(Address destination, SearchId search_id, OfferId offer_id,
                                       const NodePublicKey &        destination_public_key,
                                       const TransferKey &          transfer_key,
                                       const std::vector<PartData> &parts)                      = 0;
    virtual RequestHandlePtr SendUncache(Address destination, const AHash &ahash)               = 0;
    virtual RequestHandlePtr SendConfirmTransfer(Address destination, OfferId offer_id)         = 0;

    virtual RequestHandlePtr SendRequestProxy(Address destination, PartSize part_size) = 0;
    virtual RequestHandlePtr SendInitUpload(Address destination, OfferId offer_id)     = 0;
    virtual RequestHandlePtr SendUpload(Address destination, PartSize offset,
                                        const std::vector<Byte> &data)                 = 0;
    virtual RequestHandlePtr SendFetch(Address destination, OfferId offer_id,
                                       Address drop_point)                             = 0;
    virtual RequestHandlePtr SendInitDownload(Address destination, OfferId offer_id)   = 0;
};
}  // namespace sand::protocol

#endif  // SAND_PROTOCOL_PROTOCOLMESSAGEHANDLER_HPP_
