#ifndef SAND_STORAGE_FILESTORAGEIMPL_HPP_
#define SAND_STORAGE_FILESTORAGEIMPL_HPP_

#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>

#include "filestorage.hpp"

namespace sand::storage
{
// Forward declarations
class FileStorageMetadata;
class OpenFile;

class FileStorageImpl : public FileStorage
{
public:
    FileStorageImpl(std::shared_ptr<FileStorageMetadata> file_storage_metadata);

    [[nodiscard]] bool   contains(const std::string &file_hash) const override;
    [[nodiscard]] Handle open_file_for_reading(const std::string &file_hash) override;
    [[nodiscard]] Handle open_file_for_writing(const std::string &file_hash,
        const std::string &file_name, size_t file_size, bool truncate) override;
    size_t read_file(Handle handle, size_t offset, size_t amount, uint8_t *out) override;
    size_t write_file(Handle handle, size_t offset, size_t amount, const uint8_t *in) override;
    bool   close_file(Handle handle) override;
    bool   delete_file(const std::string &file_hash) override;

private:
    [[nodiscard]] std::shared_ptr<OpenFile> get_open_file(Handle handle) const;

    const std::shared_ptr<FileStorageMetadata>  file_storage_metadata_;
    Handle                                      next_handle_;
    std::map<Handle, std::shared_ptr<OpenFile>> open_files_;
    std::map<std::string, std::set<Handle>>     open_handles_by_file_path_;
    mutable std::mutex                          mutex_;
};
}  // namespace sand::storage

#endif  // SAND_STORAGE_FILESTORAGEIMPL_HPP_
