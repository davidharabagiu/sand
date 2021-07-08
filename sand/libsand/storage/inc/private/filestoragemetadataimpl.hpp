#ifndef SAND_STORAGE_FILESTORAGEMETADATAIMPL_HPP_
#define SAND_STORAGE_FILESTORAGEMETADATAIMPL_HPP_

#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>

#include "filestoragemetadata.hpp"

namespace sand::utils
{
// Forward declarations
class Executer;
}  // namespace sand::utils

namespace sand::config
{
// Forward declarations
class Config;
}  // namespace sand::config

namespace sand::storage
{
// Forward declarations
class FileHashInterpreter;

class FileStorageMetadataImpl : public FileStorageMetadata
{
public:
    FileStorageMetadataImpl(std::unique_ptr<FileHashInterpreter> file_hash_interpreter,
        std::shared_ptr<utils::Executer> hash_compute_executer, const config::Config &cfg);
    ~FileStorageMetadataImpl() override;

    [[nodiscard]] bool        contains(const std::string &file_hash) const override;
    [[nodiscard]] std::string get_file_path(const std::string &file_hash) const override;
    std::string add(const std::string &file_hash, const std::string &file_name) override;
    bool        remove(const std::string &file_hash) override;

private:
    void                      parse_metadata_file();
    void                      add_missing_files();
    void                      write_metadata_file() const;
    [[nodiscard]] std::string full_file_path(const std::string &file_name) const;
    [[nodiscard]] bool        contains_internal(const std::string &file_hash) const;
    std::string add_internal(const std::string &file_hash, const std::string &file_name);

    const std::unique_ptr<FileHashInterpreter> file_hash_interpreter_;
    const std::shared_ptr<utils::Executer>     hash_compute_executer_;
    const std::string                          metadata_file_path_;
    const std::string                          storage_root_path_;
    std::map<std::string, std::string>         hash_to_name_map_;
    std::set<std::string>                      file_name_set_;
    mutable std::mutex                         mutex_;
};
}  // namespace sand::storage

#endif  // SAND_STORAGE_FILESTORAGEMETADATAIMPL_HPP_
