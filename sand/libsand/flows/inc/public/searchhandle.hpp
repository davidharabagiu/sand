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
    [[nodiscard]] bool                                    is_valid() const;
    [[nodiscard]] std::shared_ptr<SearchHandleImpl>       data();
    [[nodiscard]] std::shared_ptr<const SearchHandleImpl> data() const;

private:
    std::shared_ptr<SearchHandleImpl> data_;

    friend struct std::hash<SearchHandle>;
    friend bool operator==(const SearchHandle &, const SearchHandle &);
    friend bool operator<(const SearchHandle &, const SearchHandle &);
};
}  // namespace sand::flows

namespace std
{
template<>
struct hash<sand::flows::SearchHandle>
{
    std::size_t operator()(const sand::flows::SearchHandle &k)
    {
        return hash<decltype(k.data_)>()(k.data_);
    }
};
}  // namespace std

#endif  // SAND_FLOWS_SEARCHHANDLE_HPP_
