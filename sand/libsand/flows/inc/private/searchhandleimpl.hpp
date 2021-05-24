#ifndef SAND_FLOWS_SEARCHHANDLEIMPL_HPP_
#define SAND_FLOWS_SEARCHHANDLEIMPL_HPP_

#include <string>

#include "messages.hpp"

namespace sand::flows
{
struct SearchHandleImpl
{
    std::string        file_hash;
    protocol::SearchId search_id;
};
}  // namespace sand::flows

#endif  // SAND_FLOWS_SEARCHHANDLEIMPL_HPP_
