#ifndef SAND_API_SANDNODEIMPL_HPP_
#define SAND_API_SANDNODEIMPL_HPP_

#include <condition_variable>
#include <cstddef>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <boost/asio.hpp>

#include "config.hpp"
#include "filelocatorflow.hpp"
#include "filetransferflow.hpp"
#include "listenergroup.hpp"
#include "peermanagerflow.hpp"
#include "sandnodelistener.hpp"
#include "transferhandle.hpp"

namespace sand
{
// Forward declarations
class PeerManagerFlowListenerDelegate;
class FileLocatorFlowListenerDelegate;
class FileTransferFlowListenerDelegate;

namespace utils
{
// Forward declarations
class ThreadPool;
class IOThreadPool;
class Timer;
}  // namespace utils

namespace storage
{
class FileStorage;
}  // namespace storage

namespace flows
{
// Forward declarations
class SearchHandle;
}  // namespace flows

class SANDNodeImpl
{
public:
    struct ActiveTransferInfo
    {
        std::string peer;
        size_t      part_size;
        enum
        {
            UPLOADER,
            DROP_POINT,
            LIFT_PROXY
        } role;
    };

public:
    SANDNodeImpl(std::string app_data_dir_path, const std::string &config_file_name);
    ~SANDNodeImpl();

    bool register_listener(const std::shared_ptr<SANDNodeListener> &listener);
    bool unregister_listener(const std::shared_ptr<SANDNodeListener> &listener);

    bool start();
    bool stop();
    bool download_file(
        const std::string &file_hash, const std::string &file_name, std::string &error_string);

private:
    enum class State
    {
        IDLE,
        STARTING,
        RUNNING,
        STOPPING,
        ERROR,
        SEARCHING,
        DOWNLOADING
    };

    enum class UploadState
    {
        IDLE,
        WAITING_FOR_CONFIRMATION,
        UPLOADING
    };

private:
    State state() const;
    void  set_state(State new_state);
    void  on_peer_manager_flow_state_changed(flows::PeerManagerFlow::State new_state);
    void  on_file_locator_flow_state_changed(flows::FileLocatorFlow::State new_state);
    void  on_file_found(const flows::TransferHandle &transfer_handle);
    void  on_file_wanted(const flows::SearchHandle &search_handle);
    void  on_transfer_confirmed(const flows::TransferHandle &transfer_handle);
    void  on_file_transfer_flow_state_changed(flows::FileTransferFlow::State new_state);
    void  on_transfer_progress_changed(
         const flows::TransferHandle &transfer_handle, size_t bytes_transferred, size_t total_bytes);
    void on_transfer_completed(const flows::TransferHandle &transfer_handle);
    void on_transfer_error(
        const flows::TransferHandle &transfer_handle, const std::string &error_string);

    constexpr static const char *to_string(State state)
    {
        switch (state)
        {
            case State::IDLE: return "IDLE";
            case State::STARTING: return "STARTING";
            case State::RUNNING: return "RUNNING";
            case State::STOPPING: return "STOPPING";
            case State::ERROR: return "ERROR";
            default: return "INVALID_STATE";
        }
    }

    constexpr static const char *to_string(UploadState state)
    {
        switch (state)
        {
            case UploadState::IDLE: return "IDLE";
            case UploadState::WAITING_FOR_CONFIRMATION: return "WAITING_FOR_CONFIRMATION";
            case UploadState::UPLOADING: return "UPLOADING";
            default: return "INVALID_STATE";
        }
    }

private:
    State                                             state_;
    UploadState                                       upload_state_;
    flows::TransferHandle                             current_download_;
    bool                                              latest_download_succeeded_;
    std::string                                       latest_download_error_;
    flows::TransferHandle                             current_upload_;
    std::unique_ptr<utils::Timer>                     pending_transfer_confirmation_timeout_;
    const std::string                                 app_data_dir_path_;
    config::Config                                    cfg_;
    utils::ListenerGroup<SANDNodeListener>            listener_group_;
    std::unique_ptr<boost::asio::io_context>          tcp_sender_io_ctx_;
    std::unique_ptr<boost::asio::io_context>          tcp_server_io_ctx_;
    std::shared_ptr<utils::ThreadPool>                thread_pool_;
    std::shared_ptr<utils::IOThreadPool>              io_thread_pool_;
    std::shared_ptr<storage::FileStorage>             file_storage_;
    std::shared_ptr<flows::PeerManagerFlow>           peer_manager_flow_;
    std::shared_ptr<PeerManagerFlowListenerDelegate>  peer_manager_flow_listener_;
    std::unique_ptr<flows::FileLocatorFlow>           file_locator_flow_;
    std::shared_ptr<FileLocatorFlowListenerDelegate>  file_locator_flow_listener_;
    std::unique_ptr<flows::FileTransferFlow>          file_transfer_flow_;
    std::shared_ptr<FileTransferFlowListenerDelegate> file_transfer_flow_listener_;
    mutable std::mutex                                mutex_;
    mutable std::mutex                                upload_procedure_mutex_;
    std::condition_variable                           cv_waiting_for_start_;
    std::condition_variable                           cv_waiting_for_search_;
    std::condition_variable                           cv_waiting_for_download_completion_;
};
}  // namespace sand

#endif  // SAND_API_SANDNODEIMPL_HPP_
