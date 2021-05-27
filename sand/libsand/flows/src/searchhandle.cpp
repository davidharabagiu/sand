#include "searchhandle.hpp"

#include "searchhandleimpl.hpp"

namespace sand::flows
{
SearchHandle::SearchHandle(std::shared_ptr<SearchHandleImpl> data)
    : data_ {std::move(data)}
{
}

bool SearchHandle::is_valid() const
{
    return static_cast<bool>(data_);
}

std::shared_ptr<SearchHandleImpl> SearchHandle::data()
{
    return data_;
}

std::shared_ptr<const SearchHandleImpl> SearchHandle::data() const
{
    return data_;
}

SearchHandle SearchHandle::clone() const
{
    auto data_clone = std::make_shared<SearchHandleImpl>(*data_);
    return SearchHandle {data_clone};
}
}  // namespace sand::flows
