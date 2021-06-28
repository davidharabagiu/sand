#include "temporarydatastorageimpl.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sstream>

#include <boost/date_time.hpp>
#include <glog/logging.h>

namespace sand::storage
{
constexpr char const *default_locale_name = "C";
constexpr char const *time_format_string  = "%Y%m%d.%H%M%S.%f";
constexpr char const *file_prefix         = "sand";
constexpr char const *file_extension      = "sandtx";

TemporaryDataStorageImpl::TemporaryDataStorageImpl()
    : default_locale_ {default_locale_name}
    , time_format_locale_ {default_locale_, new boost::posix_time::time_facet {time_format_string}}
    , next_handle_ {1}
{}

TemporaryDataStorage::Handle TemporaryDataStorageImpl::create(size_t size)
{
    // Generate file name
    std::string file_path;
    do
    {
        std::ostringstream ss;
        ss.imbue(default_locale_);

        // Add prefix
        ss << file_prefix << '.';

        // Add time
        auto local_time = boost::posix_time::microsec_clock::local_time();
        ss.imbue(time_format_locale_);
        ss << local_time;
        ss.imbue(default_locale_);

        // Add size
        ss << '.' << size;

        // Add extension
        ss << '.' << file_extension;

        file_path = std::filesystem::temp_directory_path() / ss.str();
    } while (std::filesystem::exists(file_path));

    Handle handle = invalid_handle;

    auto storage_space = std::make_unique<StorageSpace>(file_path, size);
    if (!storage_space->is_valid())
    {
        return handle;
    }

    {
        std::lock_guard lock {mutex_};
        handle = next_handle_++;
        open_files_.emplace(handle, std::move(storage_space));
    }

    return handle;
}

bool TemporaryDataStorageImpl::start_reading(Handle handle)
{
    auto storage_space = get_storage_space(handle);
    if (!storage_space)
    {
        return false;
    }
    return storage_space->start_reading();
}

bool TemporaryDataStorageImpl::read_next_chunk(
    Handle handle, size_t max_amount, size_t &offset, size_t &amount, uint8_t *data)
{
    auto storage_space = get_storage_space(handle);
    if (!storage_space)
    {
        return false;
    }
    return storage_space->read_next_chunk(max_amount, offset, amount, data);
}

bool TemporaryDataStorageImpl::cancel_reading(Handle handle)
{
    auto storage_space = get_storage_space(handle);
    if (!storage_space)
    {
        return false;
    }
    return storage_space->cancel_reading();
}

bool TemporaryDataStorageImpl::write(Handle handle, size_t offset, size_t amount, const uint8_t *in)
{
    auto storage_space = get_storage_space(handle);
    if (!storage_space)
    {
        return false;
    }
    return storage_space->write(offset, amount, in);
}

void TemporaryDataStorageImpl::remove(Handle handle)
{
    // Keep the storage alive in order to avoid file I/O operations while the mutex is aquired
    auto storage_space = get_storage_space(handle);

    {
        std::lock_guard lock {mutex_};
        open_files_.erase(handle);
    }
}

std::shared_ptr<TemporaryDataStorageImpl::StorageSpace> TemporaryDataStorageImpl::get_storage_space(
    TemporaryDataStorage::Handle handle)
{
    std::lock_guard lock {mutex_};

    auto it = open_files_.find(handle);
    if (it == open_files_.end())
    {
        return nullptr;
    }

    return it->second;
}

TemporaryDataStorageImpl::StorageSpace::StorageSpace(std::string file_path, size_t file_size)
    : file_path_ {std::move(file_path)}
    , file_size_ {file_size}
    , read_state_ {0, 0}
    , ranges_are_merged_ {true}
    , state_ {State::INVALID}
{
    if (!create_file())
    {
        file_size_ = 0;
        return;
    }

    mapping_       = {file_path_.c_str(), boost::interprocess::read_write};
    mapped_region_ = {mapping_, boost::interprocess::read_write};
    state_         = State::WRITING;
}

TemporaryDataStorageImpl::StorageSpace::~StorageSpace()
{
    std::lock_guard lock {mutex_};
    if (state_ != State::INVALID)
    {
        boost::interprocess::file_mapping::remove(file_path_.c_str());
    }
}

bool TemporaryDataStorageImpl::StorageSpace::create_file()
{
    std::ofstream fs {file_path_, std::ios::out | std::ios::binary};
    if (!fs)
    {
        LOG(ERROR) << "Cannot open " << file_path_ << " for writing";
        return false;
    }
    fs.seekp(decltype(fs)::off_type(file_size_ - 1), std::ios::beg);
    fs.write("", 1);
    return true;
}

bool TemporaryDataStorageImpl::StorageSpace::is_valid() const
{
    std::lock_guard lock {mutex_};
    return state_ != State::INVALID;
}

bool TemporaryDataStorageImpl::StorageSpace::write(size_t offset, size_t amount, const uint8_t *in)
{
    std::lock_guard lock {mutex_};

    if (state_ != State::WRITING)
    {
        LOG(ERROR) << "Temporary storage space " << file_path_ << " not in writing state";
        return false;
    }

    if (offset + amount > file_size_)
    {
        LOG(ERROR) << "Cannot write beyond the bounds of storage " << file_path_
                   << "; storage size = " << file_size_ << "; write offset = " << offset
                   << "; write amount = " << amount;
        return false;
    }

    std::copy_n(in, amount, data() + offset);
    written_ranges_.emplace_back(offset, offset + amount);
    ranges_are_merged_ = false;

    return true;
}

bool TemporaryDataStorageImpl::StorageSpace::start_reading()
{
    std::lock_guard lock {mutex_};

    if (state_ != State::WRITING)
    {
        LOG(ERROR) << "Temporary storage space " << file_path_ << " not in writing state";
        return false;
    }

    state_ = State::READING;

    if (ranges_are_merged_)
    {
        return true;
    }

    // Sort ranges
    decltype(written_ranges_) sorted_ranges;
    sorted_ranges.swap(written_ranges_);
    std::sort(sorted_ranges.begin(), sorted_ranges.end());

    // Merge ranges
    for (const auto &r : sorted_ranges)
    {
        if (written_ranges_.empty())
        {
            written_ranges_.push_back(r);
        }
        else
        {
            auto &pr = written_ranges_[written_ranges_.size() - 1];
            if (pr.second >= r.first)
            {
                pr.second = std::max(pr.second, r.second);
            }
            else
            {
                written_ranges_.push_back(r);
            }
        }
    }

    read_state_        = {0, written_ranges_.empty() ? 0 : written_ranges_[0].first};
    ranges_are_merged_ = true;

    return true;
}

bool TemporaryDataStorageImpl::StorageSpace::read_next_chunk(
    size_t max_amount, size_t &offset, size_t &amount, uint8_t *out)
{
    ReadState read_state_copy;

    {
        std::lock_guard lock {mutex_};
        if (state_ != State::READING)
        {
            LOG(ERROR) << "Temporary storage space " << file_path_ << " not in reading state";
            return false;
        }

        if (read_state_.next_range_index >= written_ranges_.size())
        {
            // Reading is done
            cancel_reading_internal();
            return false;
        }

        // Make a copy
        read_state_copy = read_state_;

        // Compute next state
        if (read_state_.next_offset + max_amount >=
            written_ranges_[read_state_.next_range_index].second)
        {
            // Jump to next chunk
            if (size_t nri = ++read_state_.next_range_index; nri < written_ranges_.size())
            {
                read_state_.next_offset = written_ranges_[nri].first;
            }
        }
        else
        {
            // Increase offset
            read_state_.next_offset += max_amount;
        }
    }

    offset = read_state_copy.next_offset;
    amount =
        std::min(offset + max_amount, written_ranges_[read_state_copy.next_range_index].second) -
        offset;
    std::copy_n(data() + offset, amount, out);

    return true;
}

bool TemporaryDataStorageImpl::StorageSpace::cancel_reading()
{
    std::lock_guard lock {mutex_};

    if (state_ != State::READING)
    {
        LOG(ERROR) << "Temporary storage space " << file_path_ << " not in reading state";
        return false;
    }

    cancel_reading_internal();
    return true;
}

uint8_t *TemporaryDataStorageImpl::StorageSpace::data()
{
    return static_cast<uint8_t *>(mapped_region_.get_address());
}

void TemporaryDataStorageImpl::StorageSpace::cancel_reading_internal()
{
    read_state_ = {0, 0};
    state_      = State::WRITING;
}
}  // namespace sand::storage
