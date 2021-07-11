#include "filetransferflowlistenerdelegate.hpp"

namespace sand
{
void FileTransferFlowListenerDelegate::register_as_listener(flows::FileTransferFlow &flow)
{
    flow.register_listener(shared_from_this());
}

void FileTransferFlowListenerDelegate::unregister_as_listener(flows::FileTransferFlow &flow)
{
    flow.unregister_listener(shared_from_this());
}

void FileTransferFlowListenerDelegate::set_on_state_changed_cb(OnStateChangedCb &&cb)
{
    on_state_changed_cb_ = cb;
}

void FileTransferFlowListenerDelegate::set_on_transfer_progress_changed_cb(
    OnTransferProgressChangedCb &&cb)
{
    on_transfer_progress_changed_cb_ = cb;
}

void FileTransferFlowListenerDelegate::set_on_transfer_completed_cb(OnTransferCompletedCb &&cb)
{
    on_transfer_completed_cb_ = cb;
}

void FileTransferFlowListenerDelegate::set_on_transfer_error_cb(OnTransferErrorCb &&cb)
{
    on_transfer_error_cb_ = cb;
}

void FileTransferFlowListenerDelegate::on_state_changed(flows::FileTransferFlow::State new_state)
{
    if (on_state_changed_cb_)
    {
        on_state_changed_cb_(new_state);
    }
}

void FileTransferFlowListenerDelegate::on_transfer_progress_changed(
    const flows::TransferHandle &transfer_handle, size_t bytes_transferred, size_t total_bytes)
{
    if (on_transfer_progress_changed_cb_)
    {
        on_transfer_progress_changed_cb_(transfer_handle, bytes_transferred, total_bytes);
    }
}

void FileTransferFlowListenerDelegate::on_transfer_completed(
    const flows::TransferHandle &transfer_handle)
{
    if (on_transfer_completed_cb_)
    {
        on_transfer_completed_cb_(transfer_handle);
    }
}

void FileTransferFlowListenerDelegate::on_transfer_error(
    const flows::TransferHandle &transfer_handle, const std::string &error_string)
{
    if (on_transfer_error_cb_)
    {
        on_transfer_error_cb_(transfer_handle, error_string);
    }
}
}  // namespace sand
