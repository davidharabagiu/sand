#ifndef SAND_UTILS_COMPLETIONTOKEN_HPP_
#define SAND_UTILS_COMPLETIONTOKEN_HPP_

#include <cstddef>
#include <memory>

namespace sand::utils
{
class CompletionToken
{
public:
    CompletionToken();
    CompletionToken(const CompletionToken &other) = default;
    CompletionToken &operator=(const CompletionToken &rhs) = default;
    CompletionToken(CompletionToken &&other) noexcept;
    CompletionToken &  operator=(CompletionToken &&rhs) noexcept;
    void               cancel() const;
    [[nodiscard]] bool is_cancelled() const;
    void               wait_for_completion() const;
    void               complete() const;

private:
    struct Impl;
    std::shared_ptr<Impl> impl_;

    friend struct std::hash<CompletionToken>;
    friend bool operator==(const CompletionToken &, const CompletionToken &);
    friend bool operator<(const CompletionToken &, const CompletionToken &);
};
}  // namespace sand::utils

namespace std
{
template<>
struct hash<sand::utils::CompletionToken>
{
    std::size_t operator()(const sand::utils::CompletionToken &k)
    {
        return hash<decltype(k.impl_)>()(k.impl_);
    }
};
}  // namespace std

#endif  // SAND_UTILS_COMPLETIONTOKEN_HPP_
