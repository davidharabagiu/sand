#ifndef SAND_STORAGE_FILEHASHINTERPRETER_HPP_
#define SAND_STORAGE_FILEHASHINTERPRETER_HPP_

#include <cstdint>
#include <string>
#include <utility>

#include "messages.hpp"

namespace sand::storage
{
class FileHashInterpreter
{
public:
    virtual ~FileHashInterpreter() = default;

    virtual std::pair<protocol::AHash, bool> decode(const std::string &in) const     = 0;
    virtual std::string                      encode(const protocol::AHash &in) const = 0;
    virtual size_t get_file_size(const protocol::AHash &file_hash) const             = 0;
};
}  // namespace sand::storage

#endif  // SAND_STORAGE_FILEHASHINTERPRETER_HPP_