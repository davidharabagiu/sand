#ifndef SAND_FLOWS_FILELOCATORFLOWLISTENER_HPP_
#define SAND_FLOWS_FILELOCATORFLOWLISTENER_HPP_

#include <string>

#include "filelocatorflow.hpp"

namespace sand::flows
{
class FileLocatorFlowListener
{
public:
    virtual ~FileLocatorFlowListener() = default;

    virtual void on_state_changed(FileLocatorFlow::State new_state)           = 0;
    virtual void on_file_found(const TransferHandle &transfer_handle)         = 0;
    virtual void on_file_wanted(const SearchHandle &search_handle)            = 0;
    virtual void on_transfer_confirmed(const TransferHandle &transfer_handle) = 0;
};
}  // namespace sand::flows

#endif  // SAND_FLOWS_FILELOCATORFLOWLISTENER_HPP_
