#ifndef SAND_STORAGE_FILESTORAGE_HPP_
#define SAND_STORAGE_FILESTORAGE_HPP_

#include <string>

namespace sand::storage
{
class FileStorage
{
public:
    virtual ~FileStorage() = default;

    [[nodiscard]] virtual bool contains(const std::string &file_hash) const = 0;

    virtual bool read_file(
        const std::string &file_hash, size_t offset, size_t amount, uint8_t *out) = 0;
    virtual bool write_file(
        const std::string &file_hash, size_t offset, size_t amount, const uint8_t *in) = 0;
    virtual bool close_file(const std::string &file_hash)                              = 0;
    virtual bool delete_file(const std::string &file_hash)                             = 0;
};
}  // namespace sand::storage

#endif  // SAND_STORAGE_FILESTORAGE_HPP_
