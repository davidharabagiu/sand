#include "filestorageimpl.hpp"

#include <glog/logging.h>

#include "filestoragemetadata.hpp"
#include "openfile.hpp"

namespace sand::storage
{
FileStorageImpl::FileStorageImpl(std::shared_ptr<FileStorageMetadata> file_storage_metadata)
    : file_storage_metadata_ {std::move(file_storage_metadata)}
    , next_handle_ {1}
{}

bool FileStorageImpl::contains(const std::string &file_hash) const
{
    return file_storage_metadata_->contains(file_hash);
}

FileStorage::Handle FileStorageImpl::open_file_for_reading(const std::string &file_hash)
{
    Handle handle = invalid_handle;

    std::string file_path = file_storage_metadata_->get_file_path(file_hash);
    if (file_path.empty())
    {
        LOG(ERROR) << "No file with hash " << file_hash;
        return handle;
    }

    auto file = std::make_shared<OpenFile>(file_path, OpenFile::ReadMode);
    if (!file->is_valid())
    {
        return handle;
    }

    {
        std::lock_guard lock {mutex_};
        handle = next_handle_++;
        open_files_.emplace(handle, std::move(file));
        open_handles_by_file_path_[file_path].insert(handle);
    }

    return handle;
}

FileStorage::Handle FileStorageImpl::open_file_for_writing(
    const std::string &file_hash, const std::string &file_name, size_t file_size, bool truncate)
{
    Handle handle = invalid_handle;

    std::string file_path = file_storage_metadata_->add(file_hash, file_name);
    if (file_path.empty())
    {
        return handle;
        LOG(ERROR) << "Cannot add file " << file_hash << " to storage metadata";
    }

    auto file = std::make_shared<OpenFile>(file_path, OpenFile::WriteMode, file_size, truncate);
    if (!file->is_valid())
    {
        return handle;
    }

    {
        std::lock_guard lock {mutex_};
        handle = next_handle_++;
        open_files_.emplace(handle, std::move(file));
        open_handles_by_file_path_[file_path].insert(handle);
    }

    return handle;
}

size_t FileStorageImpl::read_file(Handle handle, size_t offset, size_t amount, uint8_t *out)
{
    auto file = get_open_file(handle);
    if (!file)
    {
        LOG(ERROR) << "Invalid file handle";
        return 0;
    }
    return file->read(offset, amount, out);
}

size_t FileStorageImpl::write_file(Handle handle, size_t offset, size_t amount, const uint8_t *in)
{
    auto file = get_open_file(handle);
    if (!file)
    {
        LOG(ERROR) << "Invalid file handle";
        return 0;
    }
    return file->write(offset, amount, in);
}

bool FileStorageImpl::close_file(Handle handle)
{
    std::lock_guard lock {mutex_};

    auto file = get_open_file(handle);
    if (!file)
    {
        return false;
    }

    open_files_.erase(handle);

    auto it = open_handles_by_file_path_.find(file->file_path());
    if (it == open_handles_by_file_path_.end())
    {
        LOG(FATAL) << "Internal data anomaly, assertion failed";
    }

    it->second.erase(handle);
    if (it->second.empty())
    {
        open_handles_by_file_path_.erase(it);
    }

    return true;
}

bool FileStorageImpl::delete_file(const std::string &file_hash)
{
    std::string file_path = file_storage_metadata_->get_file_path(file_hash);
    if (file_hash.empty())
    {
        return false;
    }

    {
        std::lock_guard lock {mutex_};

        // Close all handles associated with this file
        auto it = open_handles_by_file_path_.find(file_path);
        if (it != open_handles_by_file_path_.end())
        {
            for (Handle handle : it->second)
            {
                open_files_.erase(handle);
            }
            open_handles_by_file_path_.erase(it);
        }
    }

    file_storage_metadata_->remove(file_hash);
    return true;
}

std::shared_ptr<OpenFile> FileStorageImpl::get_open_file(FileStorage::Handle handle) const
{
    std::lock_guard lock {mutex_};

    auto it = open_files_.find(handle);
    if (it == open_files_.end())
    {
        return nullptr;
    }

    return it->second;
}
}  // namespace sand::storage
