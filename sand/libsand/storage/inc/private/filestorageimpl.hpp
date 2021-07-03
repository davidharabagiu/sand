#ifndef SAND_STORAGE_FILESTORAGEIMPL_HPP_
#define SAND_STORAGE_FILESTORAGEIMPL_HPP_

#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>

#include <boost/interprocess/file_mapping.hpp>
#include <boost/interprocess/mapped_region.hpp>

#include "filestorage.hpp"

namespace sand::storage
{
// Forward declarations
class FileStorageMetadata;

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
    class OpenFile
    {
    public:
        struct ReadMode_t
        {};
        static constexpr ReadMode_t ReadMode {};

        struct WriteMode_t
        {};
        static constexpr WriteMode_t WriteMode {};

        OpenFile(std::string file_path, ReadMode_t);
        OpenFile(std::string file_path, WriteMode_t, size_t file_size, bool truncate);

        OpenFile(const OpenFile &) = delete;
        OpenFile &operator=(const OpenFile &) = delete;

        OpenFile(OpenFile &&other) noexcept;
        OpenFile &operator=(OpenFile &&rhs) noexcept;

        [[nodiscard]] explicit    operator bool() const;
        [[nodiscard]] bool        is_valid() const;
        size_t                    read(size_t offset, size_t amount, uint8_t *out) const;
        size_t                    write(size_t offset, size_t amount, const uint8_t *in) const;
        [[nodiscard]] std::string file_path() const;

    private:
        enum Mode
        {
            READ,
            WRITE
        };

        bool                   map_file();
        [[nodiscard]] bool     create_file(size_t size, bool truncate) const;
        [[nodiscard]] uint8_t *file_data() const;
        [[nodiscard]] size_t   file_size() const;

        std::string                        file_path_;
        Mode                               mode_;
        boost::interprocess::file_mapping  mapping_;
        boost::interprocess::mapped_region mapped_region_;
        bool                               is_valid_;
    };

    [[nodiscard]] std::shared_ptr<OpenFile> get_open_file(Handle handle) const;

    const std::shared_ptr<FileStorageMetadata>  file_storage_metadata_;
    Handle                                      next_handle_;
    std::map<Handle, std::shared_ptr<OpenFile>> open_files_;
    std::map<std::string, std::set<Handle>>     open_handles_by_file_path_;
    mutable std::mutex                          mutex_;
};
}  // namespace sand::storage

#endif  // SAND_STORAGE_FILESTORAGEIMPL_HPP_
