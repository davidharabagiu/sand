#include "filetransferflowimpl.hpp"

#include <algorithm>
#include <sstream>

#include <glog/logging.h>

#include "aescipher.hpp"
#include "defer.hpp"
#include "filehashinterpreter.hpp"
#include "filestorage.hpp"
#include "inboundrequestdispatcher.hpp"
#include "peermanagerflow.hpp"
#include "protocolmessagehandler.hpp"
#include "searchhandleimpl.hpp"
#include "transferhandleimpl.hpp"

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

template<typename T>
std::shared_ptr<std::future<T>> make_shared_future(std::future<T> &&future)
{
    return std::make_shared<std::decay_t<decltype(future)>>(std::move(future));
}
}  // namespace

FileTransferFlowImpl::FileTransferFlowImpl(
    std::shared_ptr<protocol::ProtocolMessageHandler> protocol_message_handler,
    std::shared_ptr<InboundRequestDispatcher>         inbound_request_dispatcher,
    std::shared_ptr<PeerAddressProvider>              peer_address_provider,
    std::shared_ptr<storage::FileStorage>             file_storage,
    std::shared_ptr<storage::FileHashInterpreter>     file_hash_interpreter,
    std::shared_ptr<crypto::AESCipher> aes, std::shared_ptr<utils::Executer> executer,
    std::shared_ptr<utils::Executer> io_executer, size_t max_part_size, size_t max_chunk_size)
    : protocol_message_handler_ {std::move(protocol_message_handler)}
    , inbound_request_dispatcher_ {std::move(inbound_request_dispatcher)}
    , peer_address_provider_ {std::move(peer_address_provider)}
    , file_storage_ {std::move(file_storage)}
    , file_hash_interpreter_ {std::move(file_hash_interpreter)}
    , aes_ {std::move(aes)}
    , executer_ {std::move(executer)}
    , io_executer_ {std::move(io_executer)}
    , max_part_size_ {max_part_size}
    , max_chunk_size_ {max_chunk_size}
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
            LOG(WARNING) << "FileTransferFlow cannot be started from state " << to_string(state_);
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
    auto promise = std::make_shared<std::promise<TransferHandle>>();
    auto future  = promise->get_future();

    {
        std::lock_guard lock {mutex_};
        if (state_ != State::RUNNING)
        {
            LOG(WARNING) << "FileTransferFlow not started";
            promise->set_value(TransferHandle {});
            return future;
        }
    }

    if (!file_storage_->contains(search_handle.data()->file_hash))
    {
        LOG(ERROR) << "File " << search_handle.data()->file_hash << " not in storage";
        promise->set_value(TransferHandle {});
        return future;
    }

    auto [file_hash, decode_ok] = file_hash_interpreter_->decode(search_handle.data()->file_hash);
    if (!decode_ok)
    {
        LOG(WARNING) << "File hash decoding error: " << search_handle.data()->file_hash;
        promise->set_value(TransferHandle {});
        return future;
    }

    size_t file_size       = file_hash_interpreter_->get_file_size(file_hash);
    size_t number_of_parts = file_size / max_part_size_ + (file_size % max_part_size_ != 0);

    add_job(io_executer_,
        [this, search_handle, promise, file_size, number_of_parts](const auto &completion_token) {
            std::set<network::IPv4Address>                            drop_points;
            std::vector<protocol::OfferMessage::SecretData::PartData> parts;
            parts.reserve(number_of_parts);
            size_t current_offset = 0;

            while (drop_points.size() != number_of_parts)
            {
                auto peers = peer_address_provider_
                                 ->get_peers(int(number_of_parts - drop_points.size()), drop_points)
                                 .get();
                if (completion_token.is_cancelled())
                {
                    return;
                }

                if (peers.size() < number_of_parts)
                {
                    LOG(WARNING) << "Cannot establish drop points for transfer";
                    promise->set_value(TransferHandle {});
                    return;
                }

                for (auto a : peers)
                {
                    if (drop_points.count(a) != 0)
                    {
                        continue;
                    }

                    auto part_size = static_cast<protocol::PartSize>(
                        drop_points.size() == number_of_parts - 1 ? file_size % max_part_size_ :
                                                                    max_part_size_);

                    auto request_proxy_msg = std::make_unique<protocol::RequestProxyMessage>();
                    request_proxy_msg->request_id = rng_.next<protocol::RequestId>();
                    request_proxy_msg->part_size  = part_size;

                    auto request_proxy_reply =
                        protocol_message_handler_->send(a, std::move(request_proxy_msg)).get();
                    if (completion_token.is_cancelled())
                    {
                        return;
                    }

                    if (request_proxy_reply->status_code == protocol::StatusCode::OK)
                    {
                        drop_points.insert(a);
                        parts.push_back({a, current_offset, part_size});

                        if (drop_points.size() > number_of_parts)
                        {
                            break;
                        }

                        current_offset += part_size;
                    }
                }
            }

            std::vector<uint8_t> key, iv;
            aes_->generate_key_and_iv(crypto::AESCipher::AES128, crypto::AESCipher::CBC, key, iv);
            protocol::TransferKey transfer_key;
            std::copy(
                iv.cbegin(), iv.cend(), std::copy(key.cbegin(), key.cend(), transfer_key.begin()));

            promise->set_value(TransferHandle {std::make_shared<TransferHandleImpl>(
                *search_handle.data(), rng_.next<protocol::OfferId>(), transfer_key, parts)});
        });

    return future;
}

bool FileTransferFlowImpl::send_file(const TransferHandle &transfer_handle)
{
    {
        std::lock_guard lock {mutex_};
        if (state_ != State::RUNNING)
        {
            LOG(WARNING) << "FileTransferFlow not started";
            return false;
        }
    }

    if (!transfer_handle.is_valid())
    {
        return false;
    }

    {
        std::lock_guard lock {mutex_};
        if (outbound_transfers_.insert(transfer_handle.data()->offer_id).second == false)
        {
            LOG(WARNING) << "Transfer for offer_id " << transfer_handle.data()->offer_id
                         << " already in progress";
            return false;
        }
    }

    const std::string &file_hash    = transfer_handle.data()->search_handle.file_hash;
    auto [bin_file_hash, decode_ok] = file_hash_interpreter_->decode(file_hash);
    if (!decode_ok)
    {
        LOG(WARNING) << "File hash decoding error: " << file_hash;
        return false;
    }

    size_t file_size = file_hash_interpreter_->get_file_size(bin_file_hash);

    add_job(io_executer_, [this, file_hash, file_size, transfer_handle](
                              const auto &completion_token) {
        protocol::OfferId offer_id = transfer_handle.data()->offer_id;

        // Send InitUpload messages
        for (const auto &part_data : transfer_handle.data()->parts)
        {
            auto msg        = std::make_unique<protocol::InitUploadMessage>();
            msg->request_id = rng_.next<protocol::RequestId>();
            msg->offer_id   = offer_id;
            auto reply =
                protocol_message_handler_->send(part_data.drop_point, std::move(msg)).get();
            if (completion_token.is_cancelled())
            {
                return;
            }

            std::ostringstream transfer_error;

            if (reply->status_code == protocol::StatusCode::UNREACHABLE)
            {
                transfer_error << "Drop point "
                               << network::conversion::to_string(part_data.drop_point)
                               << " disconnected";
                LOG(WARNING) << transfer_error.str();
            }
            else if (reply->status_code == protocol::StatusCode::DENY)
            {
                transfer_error << "Drop point "
                               << network::conversion::to_string(part_data.drop_point)
                               << " refused transfer";
                LOG(WARNING) << transfer_error.str();
            }
            else
            {
                transfer_error << "Unknown error while initiating upload to drop point "
                               << network::conversion::to_string(part_data.drop_point);
                LOG(WARNING) << transfer_error.str();
            }

            if (reply->status_code != protocol::StatusCode::OK)
            {
                std::lock_guard lock {mutex_};
                outbound_transfers_.erase(offer_id);
                listener_group_.notify(&FileTransferFlowListener::on_transfer_error,
                    transfer_handle, transfer_error.str());
                return;
            }
        }

        // Send file parts
        std::vector<std::promise<bool>> part_upload_promises;
        part_upload_promises.reserve(transfer_handle.data()->parts.size());
        size_t total_bytes_transferred = 0;

        for (const auto &part_data : transfer_handle.data()->parts)
        {
            auto &promise = part_upload_promises.emplace_back();

            add_job(io_executer_, [this, &promise, &file_hash, offer_id, &transfer_handle,
                                      &part_data, &total_bytes_transferred,
                                      &file_size](const auto &completion_token) {
                bool success = false;
                DEFER(promise.set_value(success));

                size_t bytes_transferred = 0;
                while (bytes_transferred != part_data.part_size)
                {
                    size_t chunk_size =
                        std::min(max_chunk_size_, part_data.part_size - bytes_transferred);

                    auto msg        = std::make_unique<protocol::UploadMessage>();
                    msg->request_id = rng_.next<protocol::RequestId>();
                    msg->offset     = protocol::PartSize(bytes_transferred);
                    msg->data.resize(chunk_size);

                    bool read_ok = file_storage_->read_file(file_hash,
                        part_data.part_offset + bytes_transferred, chunk_size, msg->data.data());
                    if (completion_token.is_cancelled())
                    {
                        return;
                    }

                    std::ostringstream transfer_error;
                    if (!read_ok)
                    {
                        std::lock_guard lock {mutex_};
                        outbound_transfers_.erase(offer_id);
                        transfer_error << "Cannot read file " << file_hash;
                        listener_group_.notify(&FileTransferFlowListener::on_transfer_error,
                            transfer_handle, transfer_error.str());
                        LOG(ERROR) << transfer_error.str();
                    }

                    auto reply =
                        protocol_message_handler_->send(part_data.drop_point, std::move(msg)).get();
                    if (completion_token.is_cancelled())
                    {
                        return;
                    }

                    if (reply->status_code == protocol::StatusCode::UNREACHABLE)
                    {
                        transfer_error << "Drop point "
                                       << network::conversion::to_string(part_data.drop_point)
                                       << " disconnected";
                        LOG(WARNING) << transfer_error.str();
                    }
                    else if (reply->status_code == protocol::StatusCode::DENY)
                    {
                        transfer_error << "Drop point "
                                       << network::conversion::to_string(part_data.drop_point)
                                       << " refused transfer";
                        LOG(WARNING) << transfer_error.str();
                    }
                    else
                    {
                        transfer_error << "Unknown error while uploading to drop point "
                                       << network::conversion::to_string(part_data.drop_point);
                        LOG(WARNING) << transfer_error.str();
                    }

                    if (reply->status_code != protocol::StatusCode::OK)
                    {
                        std::lock_guard lock {mutex_};
                        outbound_transfers_.erase(offer_id);
                        listener_group_.notify(&FileTransferFlowListener::on_transfer_error,
                            transfer_handle, transfer_error.str());
                        return;
                    }

                    bytes_transferred += chunk_size;

                    std::lock_guard lock {mutex_};
                    total_bytes_transferred += chunk_size;
                    listener_group_.notify(&FileTransferFlowListener::on_transfer_progress_changed,
                        transfer_handle, total_bytes_transferred, file_size);
                }

                success = true;
            });
        }

        for (auto &promise : part_upload_promises)
        {
            bool success = promise.get_future().get();
            if (completion_token.is_cancelled() || !success)
            {
                return;
            }
        }

        std::lock_guard lock {mutex_};
        outbound_transfers_.erase(offer_id);
        listener_group_.notify(&FileTransferFlowListener::on_transfer_completed, transfer_handle);
    });

    return true;
}

bool FileTransferFlowImpl::receive_file(const TransferHandle & /*transfer_handle*/)
{
    return false;
}

bool FileTransferFlowImpl::cancel_transfer(const TransferHandle & /*transfer_handle*/)
{
    return false;
}

void FileTransferFlowImpl::handle_request_proxy(
    network::IPv4Address /*from*/, const protocol::RequestProxyMessage & /*msg*/)
{
}

void FileTransferFlowImpl::handle_init_upload(
    network::IPv4Address /*from*/, const protocol::InitUploadMessage & /*msg*/)
{
}

void FileTransferFlowImpl::handle_upload(
    network::IPv4Address /*from*/, const protocol::UploadMessage & /*msg*/)
{
}

void FileTransferFlowImpl::handle_fetch(
    network::IPv4Address /*from*/, const protocol::FetchMessage & /*msg*/)
{
}

void FileTransferFlowImpl::handle_init_download(
    network::IPv4Address /*from*/, const protocol::InitDownloadMessage & /*msg*/)
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

utils::CompletionToken FileTransferFlowImpl::add_job(
    const std::shared_ptr<utils::Executer> &executer, utils::Executer::Job &&job)
{
    if (state_ != State::RUNNING)
    {
        return {};
    }

    std::lock_guard lock {mutex_};
    return *running_jobs_
                .insert(executer->add_job(
                    [this, job = std::move(job)](const utils::CompletionToken &completion_token) {
                        job(completion_token);
                        std::lock_guard lock {mutex_};
                        running_jobs_.erase(completion_token);
                    }))
                .first;
}
}  // namespace sand::flows
