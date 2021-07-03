#include "temporarydatastorageimpl.hpp"

#include <filesystem>
#include <sstream>

#include <boost/date_time.hpp>

#include "temporarystoragespace.hpp"

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

    auto storage_space = std::make_unique<TemporaryStorageSpace>(file_path, size);
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

std::shared_ptr<TemporaryStorageSpace> TemporaryDataStorageImpl::get_storage_space(
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
}  // namespace sand::storage
