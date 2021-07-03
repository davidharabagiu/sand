#ifndef SAND_STORAGE_TEMPORARYTemporaryStorageSpace_HPP_
#define SAND_STORAGE_TEMPORARYTemporaryStorageSpace_HPP_

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include <boost/interprocess/file_mapping.hpp>
#include <boost/interprocess/mapped_region.hpp>

namespace sand::storage
{
class TemporaryStorageSpace
{
public:
    TemporaryStorageSpace(std::string file_path, size_t file_size);
    ~TemporaryStorageSpace();
    [[nodiscard]] bool is_valid() const;
    bool               write(size_t offset, size_t amount, const uint8_t *in);
    bool               start_reading();
    bool read_next_chunk(size_t max_amount, size_t &offset, size_t &amount, uint8_t *data);
    bool cancel_reading();

private:
    enum class State
    {
        INVALID,
        WRITING,
        READING
    };

    struct ReadState
    {
        size_t next_range_index;
        size_t next_offset;
    };

    bool     create_file();
    uint8_t *data();
    void     cancel_reading_internal();

    std::string                            file_path_;
    size_t                                 file_size_;
    boost::interprocess::file_mapping      mapping_;
    boost::interprocess::mapped_region     mapped_region_;
    std::vector<std::pair<size_t, size_t>> written_ranges_;
    ReadState                              read_state_;
    bool                                   ranges_are_merged_;
    State                                  state_;
    mutable std::mutex                     mutex_;
};
}  // namespace sand::storage

#endif  // SAND_STORAGE_TEMPORARYTemporaryStorageSpace_HPP_
