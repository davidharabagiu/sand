#ifndef SAND_API_FILETRANSFERFLOWLISTENERDELEGATE_HPP_
#define SAND_API_FILETRANSFERFLOWLISTENERDELEGATE_HPP_

#include <functional>
#include <memory>

#include "filetransferflow.hpp"
#include "filetransferflowlistener.hpp"

namespace sand
{
class FileTransferFlowListenerDelegate
    : public flows::FileTransferFlowListener
    , public std::enable_shared_from_this<FileTransferFlowListenerDelegate>
{
public:
    using OnStateChangedCb = std::function<void(flows::FileTransferFlow::State)>;
    using OnTransferProgressChangedCb =
        std::function<void(const flows::TransferHandle &, size_t, size_t)>;
    using OnTransferCompletedCb = std::function<void(const flows::TransferHandle &)>;
    using OnTransferErrorCb =
        std::function<void(const flows::TransferHandle &, const std::string &)>;

    void register_as_listener(flows::FileTransferFlow &flow);
    void unregister_as_listener(flows::FileTransferFlow &flow);
    void set_on_state_changed_cb(OnStateChangedCb &&cb);
    void set_on_transfer_progress_changed_cb(OnTransferProgressChangedCb &&cb);
    void set_on_transfer_completed_cb(OnTransferCompletedCb &&cb);
    void set_on_transfer_error_cb(OnTransferErrorCb &&cb);

public:  // from flows::FileTransferFlowListener
    void on_state_changed(flows::FileTransferFlow::State new_state) override;
    void on_transfer_progress_changed(const flows::TransferHandle &transfer_handle,
        size_t bytes_transferred, size_t total_bytes) override;
    void on_transfer_completed(const flows::TransferHandle &transfer_handle) override;
    void on_transfer_error(
        const flows::TransferHandle &transfer_handle, const std::string &error_string) override;

private:
    OnStateChangedCb            on_state_changed_cb_;
    OnTransferProgressChangedCb on_transfer_progress_changed_cb_;
    OnTransferCompletedCb       on_transfer_completed_cb_;
    OnTransferErrorCb           on_transfer_error_cb_;
};
}  // namespace sand

#endif  // SAND_API_FILETRANSFERFLOWLISTENERDELEGATE_HPP_
