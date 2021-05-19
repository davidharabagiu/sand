#include "completiontoken.hpp"

#include <atomic>
#include <future>

namespace sand::utils
{
struct CompletionToken::Impl
{
    std::promise<void> promise_complete;
    std::future<void>  future_complete;
    std::atomic_bool   cancelled;

    Impl()
        : future_complete {promise_complete.get_future()}
        , cancelled {false}
    {
    }
};

CompletionToken::CompletionToken()
    : impl_ {std::make_shared<Impl>()}
{
}

CompletionToken::CompletionToken(CompletionToken &&other) noexcept
    : impl_ {std::move(other.impl_)}
{
}

CompletionToken &CompletionToken::operator=(CompletionToken &&rhs) noexcept
{
    impl_ = std::move(rhs.impl_);
    return *this;
}

void CompletionToken::cancel() const
{
    impl_->cancelled = true;
}

bool CompletionToken::is_cancelled() const
{
    return impl_->cancelled;
}

void CompletionToken::wait_for_completion() const
{
    impl_->future_complete.wait();
}

void CompletionToken::complete() const
{
    impl_->promise_complete.set_value();
}

bool operator==(const CompletionToken &lhs, const CompletionToken &rhs)
{
    return lhs.impl_ == rhs.impl_;
}

bool operator<(const CompletionToken &lhs, const CompletionToken &rhs)
{
    return lhs.impl_ < rhs.impl_;
}
}  // namespace sand::utils
