#ifndef SAND_FLOWS_TRANSFERHANDLEIMPL_HPP_
#define SAND_FLOWS_TRANSFERHANDLEIMPL_HPP_

#include <memory>
#include <vector>

#include "messages.hpp"
#include "searchhandleimpl.hpp"

namespace sand::flows
{
struct TransferHandleImpl
{
    using PartData = protocol::OfferMessage::SecretData::PartData;

    SearchHandleImpl      search_handle;
    protocol::OfferId     offer_id;
    protocol::TransferKey transfer_key;
    std::vector<PartData> parts;

    TransferHandleImpl(SearchHandleImpl a_search_handle, protocol::OfferId a_offer_id,
        protocol::TransferKey a_transfer_key, std::vector<PartData> a_parts)
        : search_handle {std::move(a_search_handle)}
        , offer_id {a_offer_id}
        , transfer_key {a_transfer_key}
        , parts {std::move(a_parts)}
    {
    }

    TransferHandleImpl(const TransferHandleImpl &other) = default;
    TransferHandleImpl &operator=(const TransferHandleImpl &other) = default;

    TransferHandleImpl(TransferHandleImpl &&other) noexcept
        : search_handle {std::move(other.search_handle)}
        , offer_id {other.offer_id}
        , transfer_key {other.transfer_key}
        , parts {std::move(other.parts)}
    {
        other.offer_id = 0;
        other.transfer_key.fill(0);
    }

    TransferHandleImpl &operator=(TransferHandleImpl &&rhs) noexcept
    {
        search_handle = std::move(rhs.search_handle);
        offer_id      = rhs.offer_id;
        rhs.offer_id  = 0;
        transfer_key  = rhs.transfer_key;
        rhs.transfer_key.fill(0);
        parts = std::move(rhs.parts);
        return *this;
    }
};
}  // namespace sand::flows

#endif  // SAND_FLOWS_TRANSFERHANDLEIMPL_HPP_
