#ifndef SAND_FLOWS_SEARCHHANDLEIMPL_HPP_
#define SAND_FLOWS_SEARCHHANDLEIMPL_HPP_

#include <memory>
#include <string>

#include "messages.hpp"

namespace sand::flows
{
struct SearchHandleImpl
{
    std::string        file_hash;
    protocol::SearchId search_id;
    std::string        sender_public_key;

    SearchHandleImpl(
        std::string a_file_hash, protocol::SearchId a_search_id, std::string a_sender_public_key)
        : file_hash {std::move(a_file_hash)}
        , search_id {a_search_id}
        , sender_public_key {std::move(a_sender_public_key)}
    {
    }

    SearchHandleImpl(const SearchHandleImpl &) = default;
    SearchHandleImpl &operator=(const SearchHandleImpl &) = default;

    SearchHandleImpl(SearchHandleImpl &&other) noexcept
        : file_hash {std::move(other.file_hash)}
        , search_id {other.search_id}
        , sender_public_key {std::move(other.sender_public_key)}
    {
        other.search_id = 0;
    }

    SearchHandleImpl &operator=(SearchHandleImpl &&rhs) noexcept
    {
        file_hash         = std::move(rhs.file_hash);
        search_id         = rhs.search_id;
        rhs.search_id     = 0;
        sender_public_key = std::move(rhs.sender_public_key);
        return *this;
    }
};
}  // namespace sand::flows

#endif  // SAND_FLOWS_SEARCHHANDLEIMPL_HPP_
