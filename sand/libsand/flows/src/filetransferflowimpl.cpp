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
    inbound_request_dispatcher_->set_callback<protocol::RequestDropPointMessage>([this](auto &&p1,
                                                                                     auto &&   p2) {
        handle_request_drop_point(std::forward<decltype(p1)>(p1), std::forward<decltype(p2)>(p2));
    });
    inbound_request_dispatcher_->set_callback<protocol::RequestLiftProxyMessage>([this](auto &&p1,
                                                                                     auto &&   p2) {
        handle_request_lift_proxy(std::forward<decltype(p1)>(p1), std::forward<decltype(p2)>(p2));
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
    inbound_request_dispatcher_->unset_callback<protocol::RequestDropPointMessage>();
    inbound_request_dispatcher_->unset_callback<protocol::RequestLiftProxyMessage>();
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

                if (peers.size() + drop_points.size() < number_of_parts)
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

                    auto request_proxy_msg = std::make_unique<protocol::RequestDropPointMessage>();
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

    const std::string &file_hash    = transfer_handle.data()->search_handle.file_hash;
    auto [bin_file_hash, decode_ok] = file_hash_interpreter_->decode(file_hash);
    if (!decode_ok)
    {
        LOG(WARNING) << "File hash decoding error: " << file_hash;
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

    size_t file_size = file_hash_interpreter_->get_file_size(bin_file_hash);

    add_job(io_executer_, [this, file_hash, file_size, transfer_handle](
                              const auto &completion_token) {
        protocol::OfferId offer_id = transfer_handle.data()->offer_id;

        if (check_if_outbound_transfer_cancelled_and_cleanup(offer_id))
        {
            return;
        }

        // Send InitUpload messages
        for (const auto &part_data : transfer_handle.data()->parts)
        {
            auto msg        = std::make_unique<protocol::InitUploadMessage>();
            msg->request_id = rng_.next<protocol::RequestId>();
            msg->offer_id   = offer_id;
            auto reply =
                protocol_message_handler_->send(part_data.drop_point, std::move(msg)).get();
            if (completion_token.is_cancelled() ||
                check_if_outbound_transfer_cancelled_and_cleanup(offer_id))
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
                pending_transfer_cancellations_.erase(offer_id);
                listener_group_.notify(&FileTransferFlowListener::on_transfer_error,
                    transfer_handle, transfer_error.str());
                return;
            }
        }

        // Send file parts
        std::vector<std::promise<bool>> part_upload_promises;
        part_upload_promises.reserve(transfer_handle.data()->parts.size());
        size_t total_bytes_transferred = 0;

        size_t               key_size = transfer_handle.data()->transfer_key.size() / 2;
        std::vector<uint8_t> key(key_size);
        std::vector<uint8_t> iv(key_size);
        {
            auto src = transfer_handle.data()->transfer_key.cbegin();
            std::copy_n(src, key_size, key.begin());
            std::advance(src, key_size);
            std::copy_n(src, key_size, iv.begin());
        }

        for (const auto &part_data : transfer_handle.data()->parts)
        {
            auto &promise = part_upload_promises.emplace_back();

            add_job(io_executer_, [this, &promise, &file_hash, offer_id, &transfer_handle,
                                      &part_data, &total_bytes_transferred, &file_size, &key,
                                      &iv](const auto &completion_token) {
                if (check_if_outbound_transfer_cancelled_and_cleanup(offer_id))
                {
                    return;
                }

                bool success = false;
                DEFER(promise.set_value(success));

                size_t               bytes_transferred = 0;
                std::vector<uint8_t> plain_text(max_chunk_size_);

                while (bytes_transferred != part_data.part_size)
                {
                    size_t chunk_size =
                        std::min(max_chunk_size_, part_data.part_size - bytes_transferred);

                    bool read_ok = file_storage_->read_file(file_hash,
                        part_data.part_offset + bytes_transferred, chunk_size, plain_text.data());
                    if (completion_token.is_cancelled() ||
                        check_if_outbound_transfer_cancelled_and_cleanup(offer_id))
                    {
                        return;
                    }

                    std::ostringstream transfer_error;
                    if (!read_ok)
                    {
                        std::lock_guard lock {mutex_};
                        outbound_transfers_.erase(offer_id);
                        pending_transfer_cancellations_.erase(offer_id);
                        transfer_error << "Cannot read file " << file_hash;
                        listener_group_.notify(&FileTransferFlowListener::on_transfer_error,
                            transfer_handle, transfer_error.str());
                        LOG(ERROR) << transfer_error.str();
                    }

                    auto msg        = std::make_unique<protocol::UploadMessage>();
                    msg->request_id = rng_.next<protocol::RequestId>();
                    msg->offset     = protocol::PartSize(bytes_transferred);
                    msg->data =
                        aes_->encrypt(crypto::AESCipher::CBC, key, iv, plain_text, *executer_)
                            .get();
                    if (completion_token.is_cancelled() ||
                        check_if_outbound_transfer_cancelled_and_cleanup(offer_id))
                    {
                        return;
                    }

                    if (msg->data.empty())
                    {
                        std::lock_guard lock {mutex_};
                        outbound_transfers_.erase(offer_id);
                        pending_transfer_cancellations_.erase(offer_id);
                        transfer_error << "Data encryption error";
                        listener_group_.notify(&FileTransferFlowListener::on_transfer_error,
                            transfer_handle, transfer_error.str());
                        LOG(ERROR) << transfer_error.str();
                    }

                    auto reply =
                        protocol_message_handler_->send(part_data.drop_point, std::move(msg)).get();
                    if (completion_token.is_cancelled() ||
                        check_if_outbound_transfer_cancelled_and_cleanup(offer_id))
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
                        pending_transfer_cancellations_.erase(offer_id);
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
            if (completion_token.is_cancelled() ||
                check_if_outbound_transfer_cancelled_and_cleanup(offer_id) || !success)
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

bool FileTransferFlowImpl::receive_file(const TransferHandle &transfer_handle)
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

    const std::string &file_hash    = transfer_handle.data()->search_handle.file_hash;
    auto [bin_file_hash, decode_ok] = file_hash_interpreter_->decode(file_hash);
    if (!decode_ok)
    {
        LOG(WARNING) << "File hash decoding error: " << file_hash;
        return false;
    }

    {
        std::lock_guard lock {mutex_};
        if (inbound_transfers_.insert(transfer_handle.data()->offer_id).second == false)
        {
            LOG(WARNING) << "Transfer for offer_id " << transfer_handle.data()->offer_id
                         << " already in progress";
            return false;
        }
    }

    add_job(io_executer_, [this, transfer_handle](const auto &completion_token) {
        protocol::OfferId offer_id = transfer_handle.data()->offer_id;
        if (check_if_inbound_transfer_cancelled_and_cleanup(offer_id))
        {
            return;
        }

        const auto &                   parts = transfer_handle.data()->parts;
        std::set<network::IPv4Address> lift_proxies;

        // Send RequestProxy messages
        auto next_part_it = parts.cbegin();
        while (lift_proxies.size() != parts.size())
        {
            auto peers = peer_address_provider_
                             ->get_peers(int(parts.size() - lift_proxies.size()), lift_proxies)
                             .get();
            if (completion_token.is_cancelled() ||
                check_if_inbound_transfer_cancelled_and_cleanup(offer_id))
            {
                return;
            }

            if (peers.size() < parts.size())
            {
                std::string err_string = "Cannot establish lift proxies for transfer";
                LOG(WARNING) << err_string;
                std::lock_guard lock {mutex_};
                inbound_transfers_.erase(offer_id);
                pending_transfer_cancellations_.erase(offer_id);
                listener_group_.notify(
                    &FileTransferFlowListener::on_transfer_error, transfer_handle, err_string);
                return;
            }

            for (auto a : peers)
            {
                if (lift_proxies.count(a) != 0)
                {
                    continue;
                }

                auto request_proxy_msg = std::make_unique<protocol::RequestLiftProxyMessage>();
                request_proxy_msg->request_id = rng_.next<protocol::RequestId>();
                request_proxy_msg->part_size  = next_part_it->part_size;

                auto request_proxy_reply =
                    protocol_message_handler_->send(a, std::move(request_proxy_msg)).get();
                if (completion_token.is_cancelled() ||
                    check_if_inbound_transfer_cancelled_and_cleanup(offer_id))
                {
                    return;
                }

                if (request_proxy_reply->status_code == protocol::StatusCode::OK)
                {
                    lift_proxies.insert(a);

                    if (lift_proxies.size() > parts.size())
                    {
                        break;
                    }

                    ++next_part_it;
                }
            }
        }

        // Send Fetch messages
        auto               lift_proxies_it = lift_proxies.cbegin();
        auto               parts_it        = parts.cbegin();
        std::ostringstream transfer_error;
        for (; lift_proxies_it != lift_proxies.cend(); ++lift_proxies_it, ++parts_it)
        {
            auto msg        = std::make_unique<protocol::FetchMessage>();
            msg->request_id = rng_.next<protocol::RequestId>();
            msg->offer_id   = offer_id;
            msg->drop_point = parts_it->drop_point;

            auto reply = protocol_message_handler_->send(*lift_proxies_it, std::move(msg)).get();
            if (completion_token.is_cancelled() ||
                check_if_inbound_transfer_cancelled_and_cleanup(offer_id))
            {
                return;
            }

            if (reply->status_code == protocol::StatusCode::UNREACHABLE)
            {
                transfer_error << "Lift proxy " << network::conversion::to_string(*lift_proxies_it)
                               << " disconnected";
                LOG(WARNING) << transfer_error.str();
            }
            else if (reply->status_code == protocol::StatusCode::DENY)
            {
                transfer_error << "Lift proxy " << network::conversion::to_string(*lift_proxies_it)
                               << " refused transfer";
                LOG(WARNING) << transfer_error.str();
            }
            else
            {
                transfer_error << "Unknown error while trying to reach lift proxy "
                               << network::conversion::to_string(*lift_proxies_it);
                LOG(WARNING) << transfer_error.str();
            }

            if (reply->status_code != protocol::StatusCode::OK)
            {
                std::lock_guard lock {mutex_};
                inbound_transfers_.erase(offer_id);
                pending_transfer_cancellations_.erase(offer_id);
                listener_group_.notify(&FileTransferFlowListener::on_transfer_error,
                    transfer_handle, transfer_error.str());
                return;
            }
        }
    });

    return true;
}

bool FileTransferFlowImpl::cancel_transfer(const TransferHandle &transfer_handle)
{
    protocol::OfferId offer_id = transfer_handle.data()->offer_id;

    std::lock_guard lock {mutex_};
    if (inbound_transfers_.count(offer_id) == 0 && outbound_transfers_.count(offer_id) == 0)
    {
        LOG(ERROR) << "Unknown transfer with offer id " << offer_id;
        return false;
    }
    if (pending_transfer_cancellations_.count(offer_id) != 0)
    {
        LOG(ERROR) << "Transfer with offer id " << offer_id << " already in progress";
        return false;
    }

    pending_transfer_cancellations_.insert(offer_id);
    return true;
}

void FileTransferFlowImpl::handle_request_drop_point(
    network::IPv4Address /*from*/, const protocol::RequestDropPointMessage & /*msg*/)
{
}

void FileTransferFlowImpl::handle_request_lift_proxy(
    network::IPv4Address /*from*/, const protocol::RequestLiftProxyMessage & /*msg*/)
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

bool FileTransferFlowImpl::check_if_outbound_transfer_cancelled_and_cleanup(
    protocol::OfferId offer_id)
{
    std::lock_guard lock {mutex_};
    if (pending_transfer_cancellations_.count(offer_id) != 0)
    {
        pending_transfer_cancellations_.erase(offer_id);
        outbound_transfers_.erase(offer_id);
        return true;
    }
    return false;
}

bool FileTransferFlowImpl::check_if_inbound_transfer_cancelled_and_cleanup(
    protocol::OfferId offer_id)
{
    std::lock_guard lock {mutex_};
    if (pending_transfer_cancellations_.count(offer_id) != 0)
    {
        pending_transfer_cancellations_.erase(offer_id);
        inbound_transfers_.erase(offer_id);
        return true;
    }
    return false;
}
}  // namespace sand::flows
