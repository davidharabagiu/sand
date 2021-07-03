#ifndef SAND_STORAGE_FILESTORAGEMETADATA_HPP_
#define SAND_STORAGE_FILESTORAGEMETADATA_HPP_

#include <string>

namespace sand::storage
{
class FileStorageMetadata
{
public:
    virtual ~FileStorageMetadata() = default;

    [[nodiscard]] virtual bool        contains(const std::string &file_hash) const      = 0;
    [[nodiscard]] virtual std::string get_file_path(const std::string &file_hash) const = 0;
    virtual std::string add(const std::string &file_hash, const std::string &file_name) = 0;
    virtual bool        remove(const std::string &file_hash)                            = 0;
};
}  // namespace sand::storage

#endif  // SAND_STORAGE_FILESTORAGEMETADATA_HPP_
