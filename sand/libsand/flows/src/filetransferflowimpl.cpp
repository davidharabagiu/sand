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
constexpr protocol::PartSize ENCRYPTION_BLOCK_SIZE = 16;

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
    std::shared_ptr<storage::TemporaryDataStorage>    temporary_storage,
    std::shared_ptr<crypto::AESCipher> aes, std::shared_ptr<utils::Executer> executer,
    std::shared_ptr<utils::Executer> io_executer, size_t max_part_size, size_t max_chunk_size,
    size_t max_temp_storage_size)
    : protocol_message_handler_ {std::move(protocol_message_handler)}
    , inbound_request_dispatcher_ {std::move(inbound_request_dispatcher)}
    , peer_address_provider_ {std::move(peer_address_provider)}
    , file_storage_ {std::move(file_storage)}
    , file_hash_interpreter_ {std::move(file_hash_interpreter)}
    , temporary_storage_ {std::move(temporary_storage)}
    , aes_ {std::move(aes)}
    , executer_ {std::move(executer)}
    , io_executer_ {std::move(io_executer)}
    , max_part_size_ {max_part_size}
    , max_chunk_size_ {max_chunk_size}
    , max_temp_storage_size_ {max_temp_storage_size}
    , commited_temp_storage_ {0}
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

    add_job(io_executer_, [this, search_handle, promise, file_size, number_of_parts](
                              const auto &completion_token) {
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

                protocol::PartSize padded_part_size = part_size;
                if (padded_part_size % ENCRYPTION_BLOCK_SIZE != 0)
                {
                    padded_part_size =
                        (padded_part_size / ENCRYPTION_BLOCK_SIZE + 1) * ENCRYPTION_BLOCK_SIZE;
                }

                auto request_drop_point_msg = std::make_unique<protocol::RequestDropPointMessage>();
                request_drop_point_msg->request_id = rng_.next<protocol::RequestId>();
                request_drop_point_msg->part_size  = padded_part_size;

                auto request_drop_point_reply =
                    protocol_message_handler_->send(a, std::move(request_drop_point_msg)).get();
                if (completion_token.is_cancelled())
                {
                    return;
                }

                if (request_drop_point_reply->status_code == protocol::StatusCode::OK)
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
                        return;
                    }

                    auto msg        = std::make_unique<protocol::UploadMessage>();
                    msg->request_id = rng_.next<protocol::RequestId>();
                    msg->offer_id   = offer_id;
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
                        return;
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
                file_storage_->close_file(file_hash);
                return;
            }
        }

        std::lock_guard lock {mutex_};
        outbound_transfers_.erase(offer_id);
        listener_group_.notify(&FileTransferFlowListener::on_transfer_completed, transfer_handle);
        file_storage_->close_file(file_hash);
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

                protocol::PartSize padded_part_size = next_part_it->part_size;
                if (padded_part_size % ENCRYPTION_BLOCK_SIZE != 0)
                {
                    padded_part_size =
                        (padded_part_size / ENCRYPTION_BLOCK_SIZE + 1) * ENCRYPTION_BLOCK_SIZE;
                }

                auto request_lift_proxy_msg = std::make_unique<protocol::RequestLiftProxyMessage>();
                request_lift_proxy_msg->request_id = rng_.next<protocol::RequestId>();
                request_lift_proxy_msg->part_size  = padded_part_size;

                auto request_lift_proxy_reply =
                    protocol_message_handler_->send(a, std::move(request_lift_proxy_msg)).get();
                if (completion_token.is_cancelled() ||
                    check_if_inbound_transfer_cancelled_and_cleanup(offer_id))
                {
                    return;
                }

                if (request_lift_proxy_reply->status_code == protocol::StatusCode::OK)
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
    network::IPv4Address from, const protocol::RequestDropPointMessage &msg)
{
    {
        std::lock_guard lock {mutex_};

        if (state_ != State::RUNNING)
        {
            LOG(WARNING) << "FileTransferFlow not started. Ignoring message.";
            return;
        }
    }

    add_job(io_executer_, [this, from, msg](const auto & /*completion_token*/) {
        auto reply        = std::make_unique<protocol::BasicReply>(msg.message_code);
        reply->request_id = msg.request_id;

        {
            std::unique_lock lock {mutex_};
            if (commited_temp_storage_ + msg.part_size > max_temp_storage_size_)
            {
                lock.unlock();
                LOG(INFO) << "Maximum commited temporary storage reached. Denying request.";
                reply->status_code = protocol::StatusCode::DENY;
                protocol_message_handler_->send_reply(from, std::move(reply)).wait();
                return;
            }

            if (commited_drop_point_roles_.emplace(from, msg.part_size).second == false)
            {
                lock.unlock();
                LOG(INFO) << "Drop point role already commited for uploader "
                          << network::conversion::to_string(from) << ". Denying request.";
                reply->status_code = protocol::StatusCode::DENY;
                protocol_message_handler_->send_reply(from, std::move(reply)).wait();
                return;
            }

            commited_temp_storage_ += msg.part_size;
        }

        reply->status_code = protocol::StatusCode::OK;
        protocol_message_handler_->send_reply(from, std::move(reply)).wait();
    });
}

void FileTransferFlowImpl::handle_request_lift_proxy(
    network::IPv4Address from, const protocol::RequestLiftProxyMessage &msg)
{
}

void FileTransferFlowImpl::handle_init_upload(
    network::IPv4Address from, const protocol::InitUploadMessage &msg)
{
    {
        std::lock_guard lock {mutex_};

        if (state_ != State::RUNNING)
        {
            LOG(WARNING) << "FileTransferFlow not started. Ignoring message.";
            return;
        }
    }

    add_job(io_executer_, [this, from, msg](const auto & /*completion_token*/) {
        auto reply        = std::make_unique<protocol::BasicReply>(msg.message_code);
        reply->request_id = msg.request_id;

        {
            std::unique_lock lock {mutex_};
            auto             it = commited_drop_point_roles_.find(from);
            if (it == commited_drop_point_roles_.end() ||
                ongoing_drop_point_transfers_.count(msg.offer_id) != 0)
            {
                lock.unlock();
                LOG(WARNING) << "Stray InitUpload message, denying request.";
                reply->status_code = protocol::StatusCode::DENY;
                protocol_message_handler_->send_reply(from, std::move(reply)).wait();
                return;
            }

            auto part_size = it->second;
            auto it2       = pending_lift_proxy_connections_.find(msg.offer_id);

            if (it2 == pending_lift_proxy_connections_.end())
            {
                // Lift proxy not yet connected, create temporary storage
                auto storage_handle = temporary_storage_->create(part_size);
                if (storage_handle == storage::TemporaryDataStorage::invalid_handle)
                {
                    lock.unlock();
                    LOG(WARNING) << "Cannot reserve temporary storage space of " << part_size
                                 << " bytes.";
                    reply->status_code = protocol::StatusCode::INTERNAL_ERROR;
                    protocol_message_handler_->send_reply(from, std::move(reply)).wait();
                    return;
                }

                ongoing_drop_point_transfers_.emplace(msg.offer_id,
                    OngoingDropPointTransferData {from, part_size, storage_handle, false, 0, 0});
            }
            else
            {
                // Lift proxy already sent InitDownload, no need for temp storage
                commited_temp_storage_ -= part_size;
                ongoing_drop_point_transfers_.emplace(msg.offer_id,
                    OngoingDropPointTransferData {from, part_size,
                        storage::TemporaryDataStorage::invalid_handle, true, it2->second, 0});
                pending_lift_proxy_connections_.erase(it2);
            }
        }

        reply->status_code = protocol::StatusCode::OK;
        protocol_message_handler_->send_reply(from, std::move(reply)).wait();
    });
}

void FileTransferFlowImpl::handle_upload(
    network::IPv4Address from, const protocol::UploadMessage &msg)
{
    {
        std::lock_guard lock {mutex_};

        if (state_ != State::RUNNING)
        {
            LOG(WARNING) << "FileTransferFlow not started. Ignoring message.";
            return;
        }
    }

    add_job(io_executer_, [this, from, msg](const auto & /*completion_token*/) {
        auto reply        = std::make_unique<protocol::BasicReply>(msg.message_code);
        reply->request_id = msg.request_id;

        std::unique_lock lock {mutex_};

        auto it = ongoing_drop_point_transfers_.find(msg.offer_id);
        if (it != ongoing_drop_point_transfers_.end())
        {
            if (it->second.uploader != from)
            {
                lock.unlock();
                LOG(WARNING) << "Unexpected upload message source";
                reply->status_code = protocol::StatusCode::DENY;
                protocol_message_handler_->send_reply(from, std::move(reply)).wait();
                return;
            }

            // This node is a drop point for this transfer
            lock.unlock();
            handle_upload_as_drop_point(from, msg);
        }
        else
        {
            lock.unlock();
            LOG(WARNING) << "Unexpected upload message";
            reply->status_code = protocol::StatusCode::DENY;
            protocol_message_handler_->send_reply(from, std::move(reply)).wait();
        }
    });
}

void FileTransferFlowImpl::handle_upload_as_drop_point(
    network::IPv4Address from, const protocol::UploadMessage &msg)
{
    // Send reply
    auto reply         = std::make_unique<protocol::BasicReply>(msg.message_code);
    reply->request_id  = msg.request_id;
    reply->status_code = protocol::StatusCode::OK;
    protocol_message_handler_->send_reply(from, std::move(reply)).wait();

    std::unique_lock lock {mutex_};

    auto it = ongoing_drop_point_transfers_.find(msg.offer_id);
    if (it == ongoing_drop_point_transfers_.end())
    {
        LOG(FATAL) << "Assertion failed: invalid call tohandle_upload_as_drop_point";
        return;
    }

    bool cleanup = false;

    if (it->second.lift_proxy_connected)
    {
        // Lift proxy connected, just forward message to it
        network::IPv4Address lift_proxy_address = it->second.lift_proxy;
        it->second.bytes_transferred += protocol::PartSize(msg.data.size());
        protocol::PartSize bytes_transferred = it->second.bytes_transferred;
        protocol::PartSize bytes_to_transfer = it->second.part_size;
        lock.unlock();

        auto forwarded_msg        = std::make_unique<protocol::UploadMessage>(msg);
        forwarded_msg->request_id = rng_.next<protocol::RequestId>();
        auto forwarded_msg_reply =
            protocol_message_handler_->send(lift_proxy_address, std::move(forwarded_msg)).get();
        if (forwarded_msg_reply->status_code != protocol::StatusCode::OK)
        {
            LOG(WARNING) << "Cannot forward Upload message to "
                         << network::conversion::to_string(lift_proxy_address)
                         << ". Got status code "
                         << static_cast<int>(forwarded_msg_reply->status_code) << ".";
            cleanup = true;
        }
        else if (bytes_transferred >= bytes_to_transfer)
        {
            // Transfer is done
            cleanup = true;
        }
    }
    else
    {
        // Unknown lift proxy address, store data chunk in temporary storage
        if (!temporary_storage_->write(
                it->second.storage_handle, msg.offset, msg.data.size(), msg.data.data()))
        {
            lock.unlock();
            LOG(ERROR) << "Cannot write to temporary storage";
            cleanup = true;
        }
    }

    if (cleanup)
    {
        lock.lock();
        it = ongoing_drop_point_transfers_.find(msg.offer_id);
        if (it == ongoing_drop_point_transfers_.end())
        {
            return;
        }
        if (!it->second.lift_proxy_connected)
        {
            commited_temp_storage_ -= it->second.part_size;
            temporary_storage_->remove(it->second.storage_handle);
        }
        commited_drop_point_roles_.erase(it->second.uploader);
        ongoing_drop_point_transfers_.erase(it);
    }
}

void FileTransferFlowImpl::handle_fetch(
    network::IPv4Address /*from*/, const protocol::FetchMessage & /*msg*/)
{
}

void FileTransferFlowImpl::handle_init_download(
    network::IPv4Address from, const protocol::InitDownloadMessage &msg)
{
    {
        std::lock_guard lock {mutex_};

        if (state_ != State::RUNNING)
        {
            LOG(WARNING) << "FileTransferFlow not started. Ignoring message.";
            return;
        }
    }

    add_job(io_executer_, [this, from, msg](const auto & /*completion_token*/) {
        auto reply        = std::make_unique<protocol::BasicReply>(msg.message_code);
        reply->request_id = msg.request_id;

        std::unique_lock lock {mutex_};

        bool failure          = false;
        bool init_upload_sent = false;

        auto it = ongoing_drop_point_transfers_.find(msg.offer_id);
        if (it == ongoing_drop_point_transfers_.end())
        {
            // InitUpload not sent yet
            if (pending_lift_proxy_connections_.emplace(msg.offer_id, from).second == false)
            {
                failure = true;
            }
        }
        else
        {
            if (it->second.lift_proxy_connected)
            {
                failure = true;
            }
            init_upload_sent = true;
        }

        if (failure)
        {
            lock.unlock();
            LOG(WARNING) << "Unexpected InitDownload message";
            reply->status_code = protocol::StatusCode::DENY;
            protocol_message_handler_->send_reply(from, std::move(reply)).wait();
            return;
        }

        if (!init_upload_sent)
        {
            // InitUpload not sent
            return;
        }

        // Send reply
        reply->status_code = protocol::StatusCode::OK;
        protocol_message_handler_->send_reply(from, std::move(reply)).wait();

        auto cleanup_fun = [&, this] {
            it = ongoing_drop_point_transfers_.find(msg.offer_id);
            if (it == ongoing_drop_point_transfers_.end())
            {
                return;
            }
            if (!it->second.lift_proxy_connected)
            {
                commited_temp_storage_ -= it->second.part_size;
                temporary_storage_->remove(it->second.storage_handle);
            }
            commited_drop_point_roles_.erase(it->second.uploader);
            ongoing_drop_point_transfers_.erase(it);
        };

        // Remember lift proxy address
        it->second.lift_proxy_connected = true;
        it->second.lift_proxy           = from;

        // Remove temporary storage
        temporary_storage_->remove(it->second.storage_handle);
        it->second.storage_handle = storage::TemporaryDataStorage::invalid_handle;
        commited_temp_storage_ -= it->second.part_size;

        // Send all temporary stored data
        auto read_handle = temporary_storage_->start_reading(it->second.storage_handle);
        if (!read_handle)
        {
            LOG(ERROR) << "Cannot read from temporary storage";
            cleanup_fun();
            return;
        }

        for (;;)
        {
            size_t               chunk_offset;
            size_t               chunk_size;
            std::vector<uint8_t> chunk_data(max_chunk_size_);
            if (!temporary_storage_->read_next_chunk(
                    read_handle, max_chunk_size_, chunk_offset, chunk_size, chunk_data.data()))
            {
                break;
            }

            auto upload_msg        = std::make_unique<protocol::UploadMessage>();
            upload_msg->request_id = rng_.next<protocol::RequestId>();
            upload_msg->offer_id   = msg.offer_id;
            upload_msg->offset     = protocol::PartSize(chunk_offset);
            upload_msg->data       = std::move(chunk_data);
            upload_msg->data.resize(chunk_size);

            auto upload_reply = protocol_message_handler_->send(from, std::move(upload_msg)).get();
            if (upload_reply->status_code != protocol::StatusCode::OK)
            {
                LOG(WARNING) << "Cannot send Upload message to "
                             << network::conversion::to_string(from) << ". Got status code "
                             << static_cast<int>(upload_reply->status_code) << ".";
                cleanup_fun();
                return;
            }

            it->second.bytes_transferred += protocol::PartSize(chunk_size);
        }

        if (it->second.bytes_transferred >= it->second.part_size)
        {
            cleanup_fun();
        }
    });
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

    for (const auto &kv : ongoing_drop_point_transfers_)
    {
        temporary_storage_->remove(kv.second.storage_handle);
    }

    outbound_transfers_.clear();
    inbound_transfers_.clear();
    pending_transfer_cancellations_.clear();
    commited_drop_point_roles_.clear();
    pending_lift_proxy_connections_.clear();
    ongoing_drop_point_transfers_.clear();
    commited_temp_storage_ = 0;

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
