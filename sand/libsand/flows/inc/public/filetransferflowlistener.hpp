#ifndef SAND_FLOWS_FILETRANSFERFLOWLISTENER_HPP_
#define SAND_FLOWS_FILETRANSFERFLOWLISTENER_HPP_

#include "filetransferflow.hpp"

namespace sand::flows
{
class FileTransferFlowListener
{
public:
    virtual ~FileTransferFlowListener() = default;

    virtual void on_state_changed(FileTransferFlow::State new_state) = 0;
    virtual void on_transfer_progress_changed(
        const TransferHandle &transfer_handle, size_t bytes_transferred, size_t total_bytes) = 0;
    virtual void on_transfer_completed(const TransferHandle &transfer_handle)                = 0;
    virtual void on_transfer_error(
        const TransferHandle &transfer_handle, const std::string &error_string) = 0;
};
}  // namespace sand::flows

#endif  // SAND_FLOWS_FILETRANSFERFLOWLISTENER_HPP_
