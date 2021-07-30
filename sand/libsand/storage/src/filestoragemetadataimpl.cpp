#include "filestoragemetadataimpl.hpp"

#include <filesystem>
#include <fstream>
#include <future>
#include <utility>

#include <glog/logging.h>
#include <nlohmann/json.hpp>

#include "defer.hpp"
#include "executer.hpp"
#include "filehashinterpreter.hpp"

constexpr char const *json_file_hash_entry_name = "hash";
constexpr char const *json_file_name_entry_name = "name";

namespace sand::storage
{
FileStorageMetadataImpl::FileStorageMetadataImpl(
    std::unique_ptr<FileHashInterpreter> file_hash_interpreter,
    std::shared_ptr<utils::Executer> hash_compute_executer, std::string metadata_file_path,
    std::string storage_path)
    : file_hash_interpreter_ {std::move(file_hash_interpreter)}
    , hash_compute_executer_ {std::move(hash_compute_executer)}
    , metadata_file_path_ {std::move(metadata_file_path)}
    , storage_path_ {std::move(storage_path)}
{
    parse_metadata_file();
    add_missing_files();
}

FileStorageMetadataImpl::~FileStorageMetadataImpl()
{
    write_metadata_file();
}

bool FileStorageMetadataImpl::contains(const std::string &file_hash) const
{
    std::lock_guard lock {mutex_};
    return contains_internal(file_hash);
}

std::string FileStorageMetadataImpl::get_file_path(const std::string &file_hash) const
{
    std::lock_guard lock {mutex_};

    auto it = hash_to_name_map_.find(file_hash);
    if (it == hash_to_name_map_.end())
    {
        return "";
    }
    return full_file_path(it->second);
}

std::string FileStorageMetadataImpl::add(const std::string &file_hash, const std::string &file_name)
{
    std::lock_guard lock {mutex_};

    if (file_hash.empty() || file_name.empty() || contains_internal(file_hash) ||
        file_name_set_.count(file_name) != 0)
    {
        return "";
    }
    return add_internal(file_hash, file_name);
}

bool FileStorageMetadataImpl::remove(const std::string &file_hash)
{
    std::lock_guard lock {mutex_};

    auto it = hash_to_name_map_.find(file_hash);
    if (it == hash_to_name_map_.end())
    {
        return false;
    }
    file_name_set_.erase(it->second);
    hash_to_name_map_.erase(it);
    return true;
}

void FileStorageMetadataImpl::parse_metadata_file()
{
    std::ifstream fs {metadata_file_path_};
    if (!fs)
    {
        LOG(INFO) << "Metadata file " << metadata_file_path_
                  << " not present, one will be generated";
        return;
    }

    nlohmann::json json_root;
    fs >> json_root;
    if (!json_root.is_array())
    {
        LOG(WARNING) << "Metadata file " << metadata_file_path_
                     << " parse error, a new one will be generated";
        return;
    }

    for (const auto &entry : json_root)
    {
        bool parse_err = false;
        DEFER({
            if (parse_err)
            {
                LOG(WARNING) << "Metadata file " << metadata_file_path_
                             << " entry parse error, skipping to next entry";
            }
        });

        if (!entry.is_object())
        {
            parse_err = true;
            continue;
        }

        auto hash_it = entry.find(json_file_hash_entry_name);
        if (hash_it == entry.end() || !hash_it->is_string())
        {
            parse_err = true;
            continue;
        }

        auto name_it = entry.find(json_file_name_entry_name);
        if (name_it == entry.end() || !name_it->is_string())
        {
            parse_err = true;
            continue;
        }

        const std::string file_hash {*hash_it};
        const std::string file_name {*name_it};

        if (!std::filesystem::exists(full_file_path(file_name)))
        {
            LOG(WARNING) << "File " << file_name << " no longer exists. Skipping metadata entry.";
            continue;
        }

        add_internal(file_hash, file_name);
    }
}

void FileStorageMetadataImpl::write_metadata_file() const
{
    auto json_root = nlohmann::json::array();

    for (const auto &[hash, name] : hash_to_name_map_)
    {
        auto &e = json_root.emplace_back();

        e[json_file_hash_entry_name] = hash;
        e[json_file_name_entry_name] = name;
    }

    std::ofstream fs {metadata_file_path_};
    fs << std::setw(4) << json_root;
}

void FileStorageMetadataImpl::add_missing_files()
{
    std::map<std::string, std::future<bool>> hashing_job_results;
    std::map<std::string, protocol::AHash>   computed_hashes;

    for (const auto &e : std::filesystem::directory_iterator {storage_path_})
    {
        if (file_name_set_.count(e.path().filename()) == 0)
        {
            protocol::AHash &result_ref =
                computed_hashes.emplace(e.path().filename(), protocol::AHash {}).first->second;
            hashing_job_results.emplace(e.path().filename(),
                file_hash_interpreter_->create_hash(e.path(), result_ref, *hash_compute_executer_));
        }
    }

    for (auto &[file_name, future] : hashing_job_results)
    {
        if (!future.get())
        {
            LOG(ERROR) << "Hashing job for file " << file_name << " failed";
            continue;
        }

        add_internal(file_hash_interpreter_->encode(computed_hashes.at(file_name)), file_name);
    }
}

std::string FileStorageMetadataImpl::full_file_path(const std::string &file_name) const
{
    return std::filesystem::path {storage_path_} / file_name;
}

bool FileStorageMetadataImpl::contains_internal(const std::string &file_hash) const
{
    return hash_to_name_map_.count(file_hash) != 0;
}

std::string FileStorageMetadataImpl::add_internal(
    const std::string &file_hash, const std::string &file_name)
{
    hash_to_name_map_.emplace(file_hash, file_name);
    file_name_set_.emplace(file_name);
    return full_file_path(file_name);
}
}  // namespace sand::storage
