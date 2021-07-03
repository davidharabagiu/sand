#include "openfile.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>

#include <glog/logging.h>

namespace sand::storage
{
OpenFile::OpenFile(std::string file_path, ReadMode_t)
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

OpenFile::OpenFile(std::string file_path, WriteMode_t, size_t file_size, bool truncate)
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

OpenFile::OpenFile(OpenFile &&other) noexcept
    : file_path_ {std::move(other.file_path_)}
    , mode_ {other.mode_}
    , mapping_ {std::move(other.mapping_)}
    , mapped_region_ {std::move(other.mapped_region_)}
    , is_valid_ {other.is_valid_}
{
    other.is_valid_ = false;
}

OpenFile &OpenFile::operator=(OpenFile &&rhs) noexcept
{
    file_path_     = std::move(rhs.file_path_);
    mode_          = rhs.mode_;
    mapping_       = std::move(rhs.mapping_);
    mapped_region_ = std::move(rhs.mapped_region_);
    is_valid_      = rhs.is_valid_;
    rhs.is_valid_  = false;
    return *this;
}

bool OpenFile::map_file()
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

bool OpenFile::create_file(size_t size, bool truncate) const
{
    std::ios::openmode mode = std::ios::out | std::ios::binary;

    bool file_exists = std::filesystem::exists(file_path_);
    if (truncate)
    {
        mode |= std::ios::trunc;
    }
    else if (file_exists)
    {
        mode |= std::ios::in;
    }

    {
        std::fstream fs {file_path_, mode};
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

bool OpenFile::is_valid() const
{
    return is_valid_;
}

OpenFile::operator bool() const
{
    return is_valid_;
}

size_t OpenFile::read(size_t offset, size_t amount, uint8_t *out) const
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

size_t OpenFile::write(size_t offset, size_t amount, const uint8_t *in) const
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

size_t OpenFile::file_size() const
{
    return mapped_region_.get_size();
}

uint8_t *OpenFile::file_data() const
{
    return static_cast<uint8_t *>(mapped_region_.get_address());
}

std::string OpenFile::file_path() const
{
    return file_path_;
}
}  // namespace sand::storage
