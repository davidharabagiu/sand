#ifndef SAND_STORAGE_TEMPORARYDATASTORAGEIMPL_HPP_
#define SAND_STORAGE_TEMPORARYDATASTORAGEIMPL_HPP_

#include <cstdint>
#include <locale>
#include <map>
#include <memory>
#include <mutex>

#include "temporarydatastorage.hpp"

namespace sand::storage
{
// Forward declarations
class TemporaryStorageSpace;

class TemporaryDataStorageImpl : public TemporaryDataStorage
{
public:
    TemporaryDataStorageImpl();

    [[nodiscard]] Handle create(size_t size) override;
    [[nodiscard]] bool   start_reading(Handle handle) override;
    [[nodiscard]] bool   read_next_chunk(
          Handle handle, size_t max_amount, size_t &offset, size_t &amount, uint8_t *data) override;
    [[nodiscard]] bool cancel_reading(Handle handle) override;
    [[nodiscard]] bool write(
        Handle handle, size_t offset, size_t amount, const uint8_t *in) override;
    void remove(Handle handle) override;

private:
    std::shared_ptr<TemporaryStorageSpace> get_storage_space(Handle handle);

    std::locale                                              default_locale_;
    std::locale                                              time_format_locale_;
    Handle                                                   next_handle_;
    std::map<Handle, std::shared_ptr<TemporaryStorageSpace>> open_files_;
    std::mutex                                               mutex_;
};
}  // namespace sand::storage

#endif  // SAND_STORAGE_TEMPORARYDATASTORAGEIMPL_HPP_
