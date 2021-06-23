#ifndef SAND_STORAGE_FILEHASHINTERPRETER_HPP_
#define SAND_STORAGE_FILEHASHINTERPRETER_HPP_

#include <cstdint>
#include <future>
#include <string>

#include "messages.hpp"

namespace sand::utils
{
class Executer;
}  // namespace sand::utils

namespace sand::storage
{
class FileHashInterpreter
{
public:
    virtual ~FileHashInterpreter() = default;

    virtual bool                      decode(const std::string &in, protocol::AHash &out) const = 0;
    [[nodiscard]] virtual std::string encode(const protocol::AHash &in) const                   = 0;
    [[nodiscard]] virtual size_t      get_file_size(const protocol::AHash &file_hash) const     = 0;
    [[nodiscard]] virtual std::future<bool> create_hash(
        const std::string &file_path, protocol::AHash &out, utils::Executer &executer) const = 0;
};
}  // namespace sand::storage

#endif  // SAND_STORAGE_FILEHASHINTERPRETER_HPP_
