#include "transferhandle.hpp"

#include "transferhandleimpl.hpp"

namespace sand::flows
{
TransferHandle::TransferHandle(std::shared_ptr<TransferHandleImpl> data)
    : data_ {std::move(data)}
{
}

bool TransferHandle::is_valid() const
{
    return static_cast<bool>(data_);
}

std::shared_ptr<TransferHandleImpl> TransferHandle::data()
{
    return data_;
}

std::shared_ptr<const TransferHandleImpl> TransferHandle::data() const
{
    return data_;
}

TransferHandle TransferHandle::clone() const
{
    return TransferHandle {std::make_shared<TransferHandleImpl>(*data_)};
}
}  // namespace sand::flows
