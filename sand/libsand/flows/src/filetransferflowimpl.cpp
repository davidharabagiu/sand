#include "filetransferflowimpl.hpp"

#include <glog/logging.h>

#include "aescipher.hpp"
#include "executer.hpp"
#include "filestorage.hpp"
#include "inboundrequestdispatcher.hpp"
#include "peermanagerflow.hpp"
#include "protocolmessagehandler.hpp"

namespace sand::flows
{
namespace
{
const char *to_string(FileTransferFlow::State state)
{
    switch (state)
    {
        case FileTransferFlow::State::IDLE: return "IDLE";
        case FileTransferFlow::State::RUNNING: return "RUNNING";
        case FileTransferFlow::State::STOPPING: return "STOPPING";
        default: return "INVALID_STATE";
    }
}
}  // namespace

FileTransferFlowImpl::FileTransferFlowImpl(
    std::shared_ptr<protocol::ProtocolMessageHandler> protocol_message_handler,
    std::shared_ptr<InboundRequestDispatcher>         inbound_request_dispatcher,
    std::shared_ptr<PeerManagerFlow>                  peer_address_provider,
    std::shared_ptr<storage::FileStorage> file_storage, std::shared_ptr<crypto::AESCipher> aes,
    std::shared_ptr<utils::Executer> executer, std::shared_ptr<utils::Executer> io_executer)
    : protocol_message_handler_ {std::move(protocol_message_handler)}
    , inbound_request_dispatcher_ {std::move(inbound_request_dispatcher)}
    , peer_address_provider_ {std::move(peer_address_provider)}
    , file_storage_ {std::move(file_storage)}
    , aes_ {std::move(aes)}
    , executer_ {std::move(executer)}
    , io_executer_ {std::move(io_executer)}
    , state_ {State::IDLE}
{
    inbound_request_dispatcher_->set_callback<protocol::RequestProxyMessage>(
        [this](auto &&p1, auto &&p2) {
            handle_request_proxy(std::forward<decltype(p1)>(p1), std::forward<decltype(p2)>(p2));
        });
    inbound_request_dispatcher_->set_callback<protocol::InitUploadMessage>(
        [this](auto &&p1, auto &&p2) {
            handle_init_upload(std::forward<decltype(p1)>(p1), std::forward<decltype(p2)>(p2));
        });
    inbound_request_dispatcher_->set_callback<protocol::UploadMessage>(
        [this](auto &&p1, auto &&p2) {
            handle_upload(std::forward<decltype(p1)>(p1), std::forward<decltype(p2)>(p2));
        });
    inbound_request_dispatcher_->set_callback<protocol::FetchMessage>([this](auto &&p1, auto &&p2) {
        handle_fetch(std::forward<decltype(p1)>(p1), std::forward<decltype(p2)>(p2));
    });
    inbound_request_dispatcher_->set_callback<protocol::InitDownloadMessage>(
        [this](auto &&p1, auto &&p2) {
            handle_init_download(std::forward<decltype(p1)>(p1), std::forward<decltype(p2)>(p2));
        });
}

FileTransferFlowImpl::~FileTransferFlowImpl()
{
    inbound_request_dispatcher_->unset_callback<protocol::RequestProxyMessage>();
    inbound_request_dispatcher_->unset_callback<protocol::InitUploadMessage>();
    inbound_request_dispatcher_->unset_callback<protocol::UploadMessage>();
    inbound_request_dispatcher_->unset_callback<protocol::FetchMessage>();
    inbound_request_dispatcher_->unset_callback<protocol::InitDownloadMessage>();

    std::unique_lock lock {mutex_};
    if (state_ == State::RUNNING)
    {
        lock.unlock();
        stop_impl();
    }
}

bool FileTransferFlowImpl::register_listener(std::shared_ptr<FileTransferFlowListener> listener)
{
    return listener_group_.add(listener);
}

bool FileTransferFlowImpl::unregister_listener(std::shared_ptr<FileTransferFlowListener> listener)
{
    return listener_group_.remove(listener);
}

FileTransferFlow::State FileTransferFlowImpl::state() const
{
    std::lock_guard lock {mutex_};
    return state_;
}

void FileTransferFlowImpl::start()
{
    {
        std::lock_guard lock {mutex_};
        if (state_ != State::IDLE)
        {
            LOG(WARNING) << "FileTransferFlow cannot be started from state " << to_string(state);
            return;
        }
    }

    set_state(State::RUNNING);
}

void FileTransferFlowImpl::stop()
{
    stop_impl();
}

std::future<TransferHandle> FileTransferFlowImpl::create_offer(const SearchHandle &search_handle)
{
    return std::future<TransferHandle>();
}

bool FileTransferFlowImpl::send_file(const TransferHandle &transfer_handle)
{
    return false;
}

bool FileTransferFlowImpl::receive_file(const TransferHandle &transfer_handle)
{
    return false;
}

bool FileTransferFlowImpl::cancel_transfer(const TransferHandle &transfer_handle)
{
    return false;
}

void FileTransferFlowImpl::on_state_changed(PeerManagerFlow::State new_state)
{
}

void FileTransferFlowImpl::on_peer_disconnected(network::IPv4Address address)
{
}

void FileTransferFlowImpl::handle_request_proxy(
    network::IPv4Address from, const protocol::RequestProxyMessage &msg)
{
}

void FileTransferFlowImpl::handle_init_upload(
    network::IPv4Address from, const protocol::InitUploadMessage &msg)
{
}

void FileTransferFlowImpl::handle_upload(
    network::IPv4Address from, const protocol::UploadMessage &msg)
{
}

void FileTransferFlowImpl::handle_fetch(
    network::IPv4Address from, const protocol::FetchMessage &msg)
{
}

void FileTransferFlowImpl::handle_init_download(
    network::IPv4Address from, const protocol::InitDownloadMessage &msg)
{
}

void FileTransferFlowImpl::set_state(FileTransferFlow::State new_state)
{
    std::lock_guard lock {mutex_};
    if (state_ != new_state)
    {
        state_ = new_state;
        listener_group_.notify(&FileTransferFlowListener::on_state_changed, new_state);
    }
}

void FileTransferFlowImpl::stop_impl()
{
    std::unique_lock lock {mutex_};

    if (state_ != State::RUNNING)
    {
        LOG(WARNING) << "FileTransferFlow cannot be stopped from state " << to_string(state_);
        return;
    }

    set_state(State::STOPPING);

    auto runnings_jobs_copy = running_jobs_;
    lock.unlock();

    for (const auto &completion_token : runnings_jobs_copy)
    {
        completion_token.cancel();
        completion_token.wait_for_completion();
    }

    lock.lock();
    if (!running_jobs_.empty())
    {
        LOG(ERROR) << "Some jobs are still running. This should not happen.";
    }
    lock.unlock();

    set_state(State::IDLE);
}
}  // namespace sand::flows
