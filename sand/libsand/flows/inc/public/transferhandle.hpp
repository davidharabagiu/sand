#ifndef SAND_FLOWS_TRANSFERHANDLE_HPP_
#define SAND_FLOWS_TRANSFERHANDLE_HPP_

#include <memory>

namespace sand::flows
{
struct TransferHandleImpl;

class TransferHandle
{
public:
    explicit TransferHandle(std::shared_ptr<TransferHandleImpl> data = nullptr);
    TransferHandle(const TransferHandle &) = default;
    TransferHandle &operator=(const TransferHandle &) = default;

    TransferHandle(TransferHandle &&other) noexcept
        : data_ {std::move(other.data_)}
    {
    }

    TransferHandle &operator=(TransferHandle &&rhs) noexcept
    {
        data_ = std::move(rhs.data_);
        return *this;
    }

    [[nodiscard]] bool                                      is_valid() const;
    [[nodiscard]] std::shared_ptr<TransferHandleImpl>       data();
    [[nodiscard]] std::shared_ptr<const TransferHandleImpl> data() const;
    [[nodiscard]] TransferHandle                            clone() const;

private:
    std::shared_ptr<TransferHandleImpl> data_;
};
}  // namespace sand::flows

#endif  // SAND_FLOWS_TRANSFERHANDLE_HPP_
