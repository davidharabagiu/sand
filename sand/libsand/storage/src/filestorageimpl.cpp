#include "filestorageimpl.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>

#include <glog/logging.h>

#include "filestoragemetadata.hpp"

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

std::shared_ptr<FileStorageImpl::OpenFile> FileStorageImpl::get_open_file(
    FileStorage::Handle handle) const
{
    std::lock_guard lock {mutex_};

    auto it = open_files_.find(handle);
    if (it == open_files_.end())
    {
        return nullptr;
    }

    return it->second;
}

FileStorageImpl::OpenFile::OpenFile(std::string file_path, ReadMode_t)
    : file_path_ {std::move(file_path)}
    , mode_ {Mode::READ}
    , is_valid_ {false}
{
    if (!map_file())
    {
        return;
    }

    is_valid_ = true;
}

FileStorageImpl::OpenFile::OpenFile(
    std::string file_path, WriteMode_t, size_t file_size, bool truncate)
    : file_path_ {std::move(file_path)}
    , mode_ {Mode::WRITE}
    , is_valid_ {false}
{
    if (!create_file(file_size, truncate) || !map_file())
    {
        return;
    }

    is_valid_ = true;
}

FileStorageImpl::OpenFile::OpenFile(FileStorageImpl::OpenFile &&other) noexcept
    : file_path_ {std::move(other.file_path_)}
    , mode_ {other.mode_}
    , mapping_ {std::move(other.mapping_)}
    , mapped_region_ {std::move(other.mapped_region_)}
    , is_valid_ {other.is_valid_}
{
    other.is_valid_ = false;
}

FileStorageImpl::OpenFile &FileStorageImpl::OpenFile::operator=(
    FileStorageImpl::OpenFile &&rhs) noexcept
{
    file_path_     = std::move(rhs.file_path_);
    mode_          = rhs.mode_;
    mapping_       = std::move(rhs.mapping_);
    mapped_region_ = std::move(rhs.mapped_region_);
    is_valid_      = rhs.is_valid_;
    rhs.is_valid_  = false;
    return *this;
}

bool FileStorageImpl::OpenFile::map_file()
{
    boost::interprocess::mode_t m =
        mode_ == READ ? boost::interprocess::read_only : boost::interprocess::read_write;

    try
    {
        mapping_ = {file_path_.c_str(), m};
    }
    catch (const boost::interprocess::interprocess_exception &e)
    {
        LOG(ERROR) << "Exception occured while opening file " << file_path_
                   << " for reading: " << e.what();
        return false;
    }

    mapped_region_ = {mapping_, m};

    return true;
}

bool FileStorageImpl::OpenFile::create_file(size_t size, bool truncate) const
{
    {
        std::ofstream fs {file_path_,
            std::ios::out | std::ios::binary | std::ios::openmode(truncate ? std::ios::trunc : 0)};
        if (!fs)
        {
            LOG(ERROR) << "Cannot open " << file_path_ << " for writing";
            return false;
        }
    }

    {
        std::error_code ec;
        std::filesystem::resize_file(file_path_, size, ec);
        if (ec)
        {
            LOG(ERROR) << "Failed attempt at resizing file " << file_path_ << " to " << size << ": "
                       << ec.message();
            return false;
        }
    }

    return true;
}

bool FileStorageImpl::OpenFile::is_valid() const
{
    return is_valid_;
}

FileStorageImpl::OpenFile::operator bool() const
{
    return is_valid_;
}

size_t FileStorageImpl::OpenFile::read(size_t offset, size_t amount, uint8_t *out) const
{
    if (!is_valid_ || mode_ != Mode::READ)
    {
        LOG(ERROR) << "File " << file_path_ << " not opened for reading";
        return 0;
    }

    if (offset >= file_size())
    {
        LOG(ERROR) << "Invalid offset for reading. "
                   << "file = " << file_path_ << "; offset = " << offset
                   << "; file size = " << file_size();
        return 0;
    }

    size_t bytes_to_read = std::min(amount, file_size() - offset);
    std::copy_n(file_data() + offset, bytes_to_read, out);

    return bytes_to_read;
}

size_t FileStorageImpl::OpenFile::write(size_t offset, size_t amount, const uint8_t *in) const
{
    if (!is_valid_ || mode_ != Mode::WRITE)
    {
        LOG(ERROR) << "File " << file_path_ << " not opened for writing";
        return 0;
    }

    if (offset >= file_size())
    {
        LOG(ERROR) << "Invalid offset for writing "
                   << "file = " << file_path_ << "; offset = " << offset
                   << "; file size = " << file_size();
        return 0;
    }

    size_t bytes_to_write = std::min(amount, file_size() - offset);
    std::copy_n(in, bytes_to_write, file_data() + offset);

    return bytes_to_write;
}

size_t FileStorageImpl::OpenFile::file_size() const
{
    return mapped_region_.get_size();
}

uint8_t *FileStorageImpl::OpenFile::file_data() const
{
    return static_cast<uint8_t *>(mapped_region_.get_address());
}

std::string FileStorageImpl::OpenFile::file_path() const
{
    return file_path_;
}
}  // namespace sand::storage
