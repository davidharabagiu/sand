#ifndef SAND_STORAGE_OPENFILE_HPP_
#define SAND_STORAGE_OPENFILE_HPP_

#include <cstddef>
#include <cstdint>
#include <string>

#include <boost/interprocess/file_mapping.hpp>
#include <boost/interprocess/mapped_region.hpp>

namespace sand::storage
{
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
}  // namespace sand::storage

#endif  // SAND_STORAGE_OPENFILE_HPP_
