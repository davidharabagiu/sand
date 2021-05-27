#ifndef SAND_FLOWS_SEARCHHANDLE_HPP_
#define SAND_FLOWS_SEARCHHANDLE_HPP_

#include <memory>

namespace sand::flows
{
struct SearchHandleImpl;

class SearchHandle
{
public:
    explicit SearchHandle(std::shared_ptr<SearchHandleImpl> data = nullptr);
    SearchHandle(const SearchHandle &) = default;
    SearchHandle &operator=(const SearchHandle &) = default;

    SearchHandle(SearchHandle &&other) noexcept
        : data_ {std::move(other.data_)}
    {
    }

    SearchHandle &operator=(SearchHandle &&rhs) noexcept
    {
        data_ = std::move(rhs.data_);
        return *this;
    }

    [[nodiscard]] bool                                    is_valid() const;
    [[nodiscard]] std::shared_ptr<SearchHandleImpl>       data();
    [[nodiscard]] std::shared_ptr<const SearchHandleImpl> data() const;
    [[nodiscard]] SearchHandle                            clone() const;

private:
    std::shared_ptr<SearchHandleImpl> data_;
};
}  // namespace sand::flows

#endif  // SAND_FLOWS_SEARCHHANDLE_HPP_
