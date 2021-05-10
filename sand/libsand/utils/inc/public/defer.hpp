#ifndef SAND_UTILS_DEFER_HPP_
#define SAND_UTILS_DEFER_HPP_

#include <functional>
#include <memory>

namespace sand::utils
{
class Defer
{
    using Call = std::function<void()>;

public:
    explicit Defer(Call call)
        : call_ {std::move(call)}
    {
    }

    Defer(Defer &&other) noexcept
        : call_ {std::move(other.call_)}
    {
    }

    Defer &operator=(Defer &&rhs) noexcept
    {
        call_ = std::move(rhs.call_);
        return *this;
    }

    Defer(const Defer &) = delete;
    Defer &operator=(const Defer &) = delete;

    ~Defer()
    {
        if (call_)
        {
            call_();
        }
    }

private:
    Call call_;
};
}  // namespace sand::utils

#ifdef __COUNTER__
#define DEFER_NEW_ID __COUNTER__
#else
#define DEFER_NEW_ID __LINE__
#endif

#define DEFER_CONCAT_TOKENS(t1, t2) t1##t2
#define DEFER_OBJ_NAME(base, id)    DEFER_CONCAT_TOKENS(base, id)
#define DEFER(...) \
    ::sand::utils::Defer DEFER_OBJ_NAME(_defer_obj_, DEFER_NEW_ID)([&] { __VA_ARGS__; })

#endif  // SAND_UTILS_DEFER_HPP_
