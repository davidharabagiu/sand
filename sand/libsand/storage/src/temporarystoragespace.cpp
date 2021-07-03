#include "temporarystoragespace.hpp"

#include <algorithm>
#include <fstream>

#include <glog/logging.h>

namespace sand::storage
{
TemporaryStorageSpace::TemporaryStorageSpace(std::string file_path, size_t file_size)
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

TemporaryStorageSpace::~TemporaryStorageSpace()
{
    std::lock_guard lock {mutex_};
    if (state_ != State::INVALID)
    {
        boost::interprocess::file_mapping::remove(file_path_.c_str());
    }
}

bool TemporaryStorageSpace::create_file()
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

bool TemporaryStorageSpace::is_valid() const
{
    std::lock_guard lock {mutex_};
    return state_ != State::INVALID;
}

bool TemporaryStorageSpace::write(size_t offset, size_t amount, const uint8_t *in)
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

bool TemporaryStorageSpace::start_reading()
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

bool TemporaryStorageSpace::read_next_chunk(
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

bool TemporaryStorageSpace::cancel_reading()
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

uint8_t *TemporaryStorageSpace::data()
{
    return static_cast<uint8_t *>(mapped_region_.get_address());
}

void TemporaryStorageSpace::cancel_reading_internal()
{
    read_state_ = {0, 0};
    state_      = State::WRITING;
}
}  // namespace sand::storage
