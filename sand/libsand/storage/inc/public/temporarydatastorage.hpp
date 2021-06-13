#ifndef SAND_STORAGE_TEMPORARYDATASTORAGE_HPP_
#define SAND_STORAGE_TEMPORARYDATASTORAGE_HPP_

#include <cstddef>
#include <cstdint>

namespace sand::storage
{
class TemporaryDataStorage
{
public:
    using Handle                           = int;
    static constexpr Handle invalid_handle = -1;
    struct ReadHandle;

    [[nodiscard]] virtual Handle      create(size_t size)                     = 0;
    [[nodiscard]] virtual ReadHandle *start_reading(Handle handle)            = 0;
    [[nodiscard]] virtual bool        read_next_chunk(ReadHandle *read_handle, size_t max_amount,
               size_t &offset, size_t &amount, uint8_t *data)                 = 0;
    [[nodiscard]] virtual bool        cancel_reading(ReadHandle *read_handle) = 0;
    [[nodiscard]] virtual bool        write(
               Handle handle, size_t offset, size_t amount, const uint8_t *in) = 0;
    virtual void remove(Handle handle)                                         = 0;
};
}  // namespace sand::storage

#endif  // SAND_STORAGE_TEMPORARYDATASTORAGE_HPP_
