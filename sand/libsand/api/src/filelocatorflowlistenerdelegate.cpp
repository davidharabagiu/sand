#include "filelocatorflowlistenerdelegate.hpp"

namespace sand
{
void FileLocatorFlowListenerDelegate::register_as_listener(flows::FileLocatorFlow &flow)
{
    flow.register_listener(shared_from_this());
}

void FileLocatorFlowListenerDelegate::unregister_as_listener(flows::FileLocatorFlow &flow)
{
    flow.unregister_listener(shared_from_this());
}

void FileLocatorFlowListenerDelegate::set_on_state_changed_cb(OnStateChangedCb &&cb)
{
    on_state_changed_cb_ = cb;
}

void FileLocatorFlowListenerDelegate::set_on_file_found_cb(OnFileFoundCb &&cb)
{
    on_file_found_cb_ = cb;
}

void FileLocatorFlowListenerDelegate::set_on_file_wanted_cb(OnFileWantedCb &&cb)
{
    on_file_wanted_cb_ = cb;
}

void FileLocatorFlowListenerDelegate::set_on_transfer_confirmed_cb(OnTransferConfirmedCb &&cb)
{
    on_transfer_confirmed_cb_ = cb;
}

void FileLocatorFlowListenerDelegate::on_state_changed(flows::FileLocatorFlow::State new_state)
{
    if (on_state_changed_cb_)
    {
        on_state_changed_cb_(new_state);
    }
}

void FileLocatorFlowListenerDelegate::on_file_found(const flows::TransferHandle &transfer_handle)
{
    if (on_file_found_cb_)
    {
        on_file_found_cb_(transfer_handle);
    }
}

void FileLocatorFlowListenerDelegate::on_file_wanted(const flows::SearchHandle &search_handle)
{
    if (on_file_wanted_cb_)
    {
        on_file_wanted_cb_(search_handle);
    }
}

void FileLocatorFlowListenerDelegate::on_transfer_confirmed(
    const flows::TransferHandle &transfer_handle)
{
    if (on_transfer_confirmed_cb_)
    {
        on_transfer_confirmed_cb_(transfer_handle);
    }
}
}  // namespace sand
