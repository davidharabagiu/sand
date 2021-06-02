#ifndef SAND_FLOWS_FILETRANSFERFLOW_HPP_
#define SAND_FLOWS_FILETRANSFERFLOW_HPP_

#include <future>
#include <memory>

#include "searchhandle.hpp"
#include "transferhandle.hpp"

namespace sand::flows
{
// Forward declarations
class FileTransferFlowListener;

class FileTransferFlow
{
public:
    enum class State
    {
        IDLE,
        RUNNING,
        STOPPING
    };

    virtual ~FileTransferFlow() = default;

    virtual bool  register_listener(std::shared_ptr<FileTransferFlowListener> listener)        = 0;
    virtual bool  unregister_listener(std::shared_ptr<FileTransferFlowListener> listener)      = 0;
    virtual State state() const                                                                = 0;
    virtual void  start()                                                                      = 0;
    virtual void  stop()                                                                       = 0;
    virtual std::future<TransferHandle> create_offer(const SearchHandle &search_handle)        = 0;
    virtual bool                        send_file(const TransferHandle &transfer_handle)       = 0;
    virtual bool                        receive_file(const TransferHandle &transfer_handle)    = 0;
    virtual bool                        cancel_transfer(const TransferHandle &transfer_handle) = 0;
};
}  // namespace sand::flows

#endif  // SAND_FLOWS_FILETRANSFERFLOW_HPP_
