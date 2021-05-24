#ifndef SAND_STORAGE_FILESTORAGE_HPP_
#define SAND_STORAGE_FILESTORAGE_HPP_

#include <string>

namespace sand::storage
{
class FileStorage
{
public:
    virtual ~FileStorage()                                                  = default;
    [[nodiscard]] virtual bool contains(const std::string &file_hash) const = 0;
};
}  // namespace sand::storage

#endif  // SAND_STORAGE_FILESTORAGE_HPP_
