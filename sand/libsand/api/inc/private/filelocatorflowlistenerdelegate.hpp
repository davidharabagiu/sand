#ifndef SAND_API_FILELOCATORFLOWLISTENERDELEGATE_HPP_
#define SAND_API_FILELOCATORFLOWLISTENERDELEGATE_HPP_

#include <functional>
#include <memory>

#include "filelocatorflow.hpp"
#include "filelocatorflowlistener.hpp"

namespace sand
{
class FileLocatorFlowListenerDelegate
    : public flows::FileLocatorFlowListener
    , public std::enable_shared_from_this<FileLocatorFlowListenerDelegate>
{
public:
    using OnStateChangedCb      = std::function<void(flows::FileLocatorFlow::State)>;
    using OnFileFoundCb         = std::function<void(const flows::TransferHandle &)>;
    using OnFileWantedCb        = std::function<void(const flows::SearchHandle &)>;
    using OnTransferConfirmedCb = std::function<void(const flows::TransferHandle &)>;

    void register_as_listener(flows::FileLocatorFlow &flow);
    void unregister_as_listener(flows::FileLocatorFlow &flow);
    void set_on_state_changed_cb(OnStateChangedCb &&cb);
    void set_on_file_found_cb(OnFileFoundCb &&cb);
    void set_on_file_wanted_cb(OnFileWantedCb &&cb);
    void set_on_transfer_confirmed_cb(OnTransferConfirmedCb &&cb);

public:  // from flows::FileLocatorFlowListener
    void on_state_changed(flows::FileLocatorFlow::State new_state) override;
    void on_file_found(const flows::TransferHandle &transfer_handle) override;
    void on_file_wanted(const flows::SearchHandle &search_handle) override;
    void on_transfer_confirmed(const flows::TransferHandle &transfer_handle) override;

private:
    OnStateChangedCb      on_state_changed_cb_;
    OnFileFoundCb         on_file_found_cb_;
    OnFileWantedCb        on_file_wanted_cb_;
    OnTransferConfirmedCb on_transfer_confirmed_cb_;
};
}  // namespace sand

#endif  // SAND_API_FILELOCATORFLOWLISTENERDELEGATE_HPP_
