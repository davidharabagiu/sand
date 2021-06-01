#include "filelocatorflowimpl.hpp"

#include <tuple>

#include <glog/logging.h>

#include "filehashcalculator.hpp"
#include "filestorage.hpp"
#include "inboundrequestdispatcher.hpp"
#include "peeraddressprovider.hpp"
#include "protocolmessagehandler.hpp"
#include "searchhandleimpl.hpp"
#include "secretdatainterpreter.hpp"
#include "transferhandleimpl.hpp"

namespace sand::flows
{
namespace
{
const char *to_string(FileLocatorFlow::State state)
{
    switch (state)
    {
        case FileLocatorFlow::State::IDLE: return "IDLE";
        case FileLocatorFlow::State::RUNNING: return "RUNNING";
        case FileLocatorFlow::State::STOPPING: return "STOPPING";
        default: return "INVALID_STATE";
    }
}
}  // namespace

FileLocatorFlowImpl::FileLocatorFlowImpl(
    std::shared_ptr<protocol::ProtocolMessageHandler> protocol_message_handler,
    std::shared_ptr<InboundRequestDispatcher>         inbound_request_dispatcher,
    std::shared_ptr<PeerAddressProvider>              peer_address_provider,
    std::shared_ptr<storage::FileStorage>             file_storage,
    std::unique_ptr<storage::FileHashCalculator>      file_hash_calculator,
    std::shared_ptr<protocol::SecretDataInterpreter>  secret_data_interpreter,
    std::shared_ptr<utils::Executer> executer, std::shared_ptr<utils::Executer> io_executer,
    std::string public_key, std::string private_key, int search_propagation_degree,
    int search_timeout_sec, int routing_table_entry_expiration_time_sec)
    : protocol_message_handler_ {std::move(protocol_message_handler)}
    , inbound_request_dispatcher_ {std::move(inbound_request_dispatcher)}
    , peer_address_provider_ {std::move(peer_address_provider)}
    , file_storage_ {std::move(file_storage)}
    , file_hash_calculator_ {std::move(file_hash_calculator)}
    , secret_data_interpreter_ {std::move(secret_data_interpreter)}
    , executer_ {std::move(executer)}
    , io_executer_ {std::move(io_executer)}
    , public_key_ {std::move(public_key)}
    , private_key_ {std::move(private_key)}
    , search_propagation_degree_ {search_propagation_degree}
    , search_timeout_sec_ {search_timeout_sec}
    , routing_table_entry_expiration_time_sec_ {routing_table_entry_expiration_time_sec}
{
    inbound_request_dispatcher_->set_callback<protocol::SearchMessage>(
        [this](auto &&p1, auto &&p2) {
            handle_search(std::forward<decltype(p1)>(p1), std::forward<decltype(p2)>(p2));
        });
    inbound_request_dispatcher_->set_callback<protocol::OfferMessage>([this](auto &&p1, auto &&p2) {
        handle_offer(std::forward<decltype(p1)>(p1), std::forward<decltype(p2)>(p2));
    });
    inbound_request_dispatcher_->set_callback<protocol::UncacheMessage>(
        [this](auto &&p1, auto &&p2) {
            handle_uncache(std::forward<decltype(p1)>(p1), std::forward<decltype(p2)>(p2));
        });
    inbound_request_dispatcher_->set_callback<protocol::ConfirmTransferMessage>(
        [this](auto &&p1, auto &&p2) {
            handle_confirm_transfer(std::forward<decltype(p1)>(p1), std::forward<decltype(p2)>(p2));
        });
}

FileLocatorFlowImpl::~FileLocatorFlowImpl()
{
    inbound_request_dispatcher_->unset_callback<protocol::SearchMessage>();
    inbound_request_dispatcher_->unset_callback<protocol::OfferMessage>();
    inbound_request_dispatcher_->unset_callback<protocol::UncacheMessage>();
    inbound_request_dispatcher_->unset_callback<protocol::ConfirmTransferMessage>();

    if (state_ == State::RUNNING)
    {
        stop_impl();
    }
}

bool FileLocatorFlowImpl::register_listener(std::shared_ptr<FileLocatorFlowListener> listener)
{
    return listener_group_.add(listener);
}

bool FileLocatorFlowImpl::unregister_listener(std::shared_ptr<FileLocatorFlowListener> listener)
{
    return listener_group_.remove(listener);
}

FileLocatorFlow::State FileLocatorFlowImpl::state() const
{
    return state_;
}

void FileLocatorFlowImpl::start()
{
    State state = state_;

    if (state != State::IDLE)
    {
        LOG(WARNING) << "FileLocatorFlow cannot be started from state " << to_string(state);
        return;
    }

    set_state(State::RUNNING);
}

void FileLocatorFlowImpl::stop()
{
    stop_impl();
}

void FileLocatorFlowImpl::stop_impl()
{
    State state = state_;

    if (state != State::RUNNING)
    {
        LOG(WARNING) << "FileLocatorFlow cannot be started from state " << to_string(state);
        return;
    }

    set_state(State::STOPPING);

    decltype(running_jobs_) runnings_jobs_copy;

    {
        std::lock_guard lock {mutex_};
        runnings_jobs_copy = running_jobs_;
    }

    for (const auto &completion_token : runnings_jobs_copy)
    {
        completion_token.cancel();
        completion_token.wait_for_completion();
    }

    if (!running_jobs_.empty())
    {
        LOG(ERROR) << "Some jobs are still running. This should not happen.";
    }

    set_state(State::IDLE);
}

SearchHandle FileLocatorFlowImpl::search(const std::string &file_hash)
{
    {
        std::lock_guard lock {mutex_};

        if (state_ != State::RUNNING)
        {
            LOG(WARNING) << "FileLocatorFlow not started. Not performing search.";
            return SearchHandle();
        }

        if (file_storage_->contains(file_hash))
        {
            LOG(WARNING) << "File with given hash already exists in local storage";
            return SearchHandle();
        }

        if (ongoing_searches_files_.count(file_hash) != 0)
        {
            LOG(WARNING) << "A search for this file is already being performed";
            return SearchHandle();
        }
    }

    // Prepare Search message
    protocol::SearchMessage msg;
    msg.search_id         = rng_.next<protocol::SearchId>();
    msg.sender_public_key = public_key_;
    if (!file_hash_calculator_->decode(file_hash, msg.file_hash.data()))
    {
        LOG(WARNING) << "Invalid file hash provided";
        return SearchHandle();
    }

    // Create SearchHandle
    SearchHandle search_handle(
        std::make_shared<SearchHandleImpl>(file_hash, msg.search_id, public_key_));

    search_loop(msg, search_handle);

    {
        std::lock_guard lock {mutex_};
        ongoing_searches_.emplace(search_handle.data()->search_id, search_handle);
        ongoing_searches_files_.insert(file_hash);
    }

    if (search_timeout_sec_ > 0)
    {
        add_timeout(std::chrono::seconds(search_timeout_sec_), [this, search_handle] {
            LOG(INFO) << "Search timeout reached, cancelling...";
            cancel_search(search_handle);
        });
    }

    return search_handle;
}

void FileLocatorFlowImpl::search_loop(
    const protocol::SearchMessage &msg, const SearchHandle &search_handle)
{
    auto proceed_with_search = [this](const std::vector<network::IPv4Address> &peers,
                                   const protocol::SearchMessage &             msg,
                                   const SearchHandle &                        search_handle) {
        // Send Search message
        auto reply_futures = std::make_shared<std::vector<
            std::pair<network::IPv4Address, std::future<std::unique_ptr<protocol::BasicReply>>>>>();
        reply_futures->reserve(peers.size());
        for (auto peer : peers)
        {
            auto unique_msg        = std::make_unique<protocol::SearchMessage>(msg);
            unique_msg->request_id = rng_.next<protocol::RequestId>();
            reply_futures->emplace_back(
                peer, protocol_message_handler_->send(peer, std::move(unique_msg)));
        }

        add_job(io_executer_, [this, search_handle, reply_futures](const auto &completion_token) {
            // Check replies
            bool success = false;

            for (auto &[a, f] : *reply_futures)
            {
                auto reply = f.get();
                if (completion_token.is_cancelled())
                {
                    return;
                }

                if (reply->status_code == protocol::StatusCode::OK)
                {
                    success = true;
                }
            }

            if (!success)
            {
                LOG(WARNING) << "Search message propagation failed.";
                cancel_search(search_handle);
            }
        });
    };

    bool                              from_cache = true;
    std::vector<network::IPv4Address> cached_peers;

    {
        std::lock_guard lock {mutex_};
        auto            search_cache_it = search_cache_.find(search_handle.data()->file_hash);
        if (search_cache_it == search_cache_.end() || search_cache_it->second.empty())
        {
            from_cache = false;
        }
        else
        {
            cached_peers.resize(search_cache_it->second.size());
            std::copy(search_cache_it->second.cbegin(), search_cache_it->second.cend(),
                cached_peers.begin());
        }
    }

    if (!from_cache)
    {
        // Find some peers
        auto peers_list_future = peer_address_provider_->get_peers(search_propagation_degree_);

        add_job(io_executer_, [this, proceed_with_search, msg, search_handle,
                                  peers_list_future = std::make_shared<decltype(peers_list_future)>(
                                      std::move(peers_list_future))](const auto &completion_token) {
            peers_list_future->wait();
            if (completion_token.is_cancelled())
            {
                return;
            }

            add_job(executer_, [this, proceed_with_search, msg, search_handle, peers_list_future](
                                   const auto & /*completion_token*/) {
                auto peers = peers_list_future->get();
                if (peers.empty())
                {
                    LOG(WARNING) << "No peers to perform search with";
                    cancel_search(search_handle);
                    return;
                }

                proceed_with_search(peers, msg, search_handle);
            });
        });
    }
    else
    {
        // Send to a random element from cache
        auto peer = cached_peers[rng_.next<size_t>(cached_peers.size() - 1)];

        // Ping the chosen peer
        auto ping        = std::make_unique<protocol::PingMessage>();
        ping->request_id = rng_.next<protocol::RequestId>();

        auto ping_future = protocol_message_handler_->send(peer, std::move(ping));
        add_job(io_executer_, [this, proceed_with_search, peer, msg, search_handle,
                                  ping_future = std::make_shared<decltype(ping_future)>(
                                      std::move(ping_future))](const auto &completion_token) {
            ping_future->wait();
            if (completion_token.is_cancelled())
            {
                return;
            }

            add_job(executer_, [this, proceed_with_search, peer, msg, search_handle, ping_future](
                                   const auto & /*completion_token*/) {
                auto ping_reply = ping_future->get();
                if (ping_reply->status_code == protocol::StatusCode::OK)
                {
                    proceed_with_search({peer}, msg, search_handle);
                }
                else
                {
                    {
                        std::lock_guard lock {mutex_};
                        search_cache_[search_handle.data()->file_hash].erase(peer);
                    }
                    search_loop(msg, search_handle);
                }
            });
        });
    }
}

bool FileLocatorFlowImpl::cancel_search(const SearchHandle &search_handle)
{
    std::lock_guard lock {mutex_};
    bool            ok = ongoing_searches_files_.erase(search_handle.data()->file_hash) != 0;
    ok &= ongoing_searches_.erase(search_handle.data()->search_id) != 0;
    return ok;
}

bool FileLocatorFlowImpl::send_offer(const TransferHandle &transfer_handle)
{
    network::IPv4Address to;

    {
        std::lock_guard lock {mutex_};

        if (sent_offers_.count(transfer_handle.data()->offer_id) != 0)
        {
            LOG(WARNING) << "Offer id duplication";
            return false;
        }

        auto it = offer_routing_table_.find(transfer_handle.data()->search_handle.search_id);
        if (it == offer_routing_table_.cend())
        {
            LOG(WARNING) << "Cannot route offer message";
            return false;
        }

        to = std::get<0>(it->second);
        offer_routing_table_.erase(it);
    }

    // Create Offer message
    auto offer        = std::make_unique<protocol::OfferMessage>();
    offer->request_id = rng_.next<protocol::RequestId>();
    offer->offer_id   = transfer_handle.data()->offer_id;
    offer->search_id  = transfer_handle.data()->search_handle.search_id;

    protocol::OfferMessage::SecretData secret_data;
    secret_data.transfer_key = transfer_handle.data()->transfer_key;
    secret_data.parts        = transfer_handle.data()->parts;
    offer->encrypted_data    = secret_data_interpreter_->encrypt_offer_message(
        secret_data, transfer_handle.data()->search_handle.sender_public_key);

    // Send Offer message
    auto reply_future = protocol_message_handler_->send(to, std::move(offer));

    add_job(io_executer_, [this, transfer_handle,
                              reply_future = std::make_shared<decltype(reply_future)>(
                                  std::move(reply_future))](const auto &completion_token) {
        reply_future->wait();
        if (completion_token.is_cancelled())
        {
            return;
        }

        add_job(
            executer_, [this, transfer_handle, reply_future](const auto & /*completion_token*/) {
                auto reply = reply_future->get();
                if (reply->status_code != protocol::StatusCode::OK)
                {
                    LOG(WARNING) << "Offer could not be sent";
                    cancel_offer(transfer_handle);
                }
            });
    });

    {
        std::lock_guard lock {mutex_};
        sent_offers_.emplace(transfer_handle.data()->offer_id, transfer_handle);
    }

    if (search_timeout_sec_ > 0)
    {
        add_timeout(std::chrono::seconds(search_timeout_sec_), [this, transfer_handle] {
            LOG(INFO) << "Offer timeout reached, cancelling...";
            cancel_offer(transfer_handle);
        });
    }

    return true;
}

bool FileLocatorFlowImpl::confirm_transfer(const TransferHandle &transfer_handle)
{
    network::IPv4Address to;

    {
        std::lock_guard lock {mutex_};

        auto it = confirm_tx_routing_table_.find(transfer_handle.data()->offer_id);
        if (it == confirm_tx_routing_table_.cend())
        {
            LOG(WARNING) << "Cannot route ConfirmTransfer message";
            return false;
        }

        to = it->second;
        confirm_tx_routing_table_.erase(it);
    }

    // Create ConfirmTransfer message
    auto confirm_tx        = std::make_unique<protocol::ConfirmTransferMessage>();
    confirm_tx->request_id = rng_.next<protocol::RequestId>();
    confirm_tx->offer_id   = transfer_handle.data()->offer_id;

    // Send ConfirmTransfer message
    auto reply_future = protocol_message_handler_->send(to, std::move(confirm_tx));

    add_job(io_executer_, [this, offer_id = transfer_handle.data()->offer_id,
                              reply_future = std::make_shared<decltype(reply_future)>(
                                  std::move(reply_future))](const auto &completion_token) {
        reply_future->wait();
        if (completion_token.is_cancelled())
        {
            return;
        }

        add_job(executer_, [offer_id, reply_future](const auto & /*completion_token*/) {
            auto reply = reply_future->get();
            if (reply->status_code != protocol::StatusCode::OK)
            {
                LOG(WARNING) << "ConfirmTransfer message for offer " << offer_id
                             << " could not be sent";
            }
        });
    });

    return true;
}

bool FileLocatorFlowImpl::cancel_offer(const TransferHandle &transfer_handle)
{
    std::lock_guard lock {mutex_};
    return sent_offers_.erase(transfer_handle.data()->offer_id) != 0;
}

void FileLocatorFlowImpl::set_state(State new_state)
{
    State state = state_;
    if (state != new_state)
    {
        state_ = new_state;
        std::lock_guard lock {mutex_};
        listener_group_.notify(&FileLocatorFlowListener::on_state_changed, new_state);
    }
}

void FileLocatorFlowImpl::handle_search(
    network::IPv4Address from, const protocol::SearchMessage &msg)
{
    add_job(executer_, [this, from, msg](const auto & /*completion_token*/) {
        std::string file_hash = file_hash_calculator_->encode(msg.file_hash.data());
        if (file_hash.empty())
        {
            LOG(WARNING) << "Received Search message with invalid file hash";
            return;
        }

        bool forward = true;

        {
            std::lock_guard lock {mutex_};
            if (file_storage_->contains(file_hash))
            {
                forward = false;
            }
        }

        if (forward)
        {
            forward_search_messsage(from, msg);
        }
        else
        {
            add_offer_routing_table_entry(from, msg.search_id, file_hash);

            auto reply         = std::make_unique<protocol::BasicReply>(msg.message_code);
            reply->request_id  = msg.request_id;
            reply->status_code = protocol::StatusCode::OK;
            wait_for_reply_confirmation(
                protocol_message_handler_->send_reply(from, std::move(reply)), msg.request_id);

            std::lock_guard lock {mutex_};
            listener_group_.notify(&FileLocatorFlowListener::on_file_wanted,
                SearchHandle {std::make_shared<SearchHandleImpl>(
                    file_hash, msg.search_id, msg.sender_public_key)});
        }
    });
}

void FileLocatorFlowImpl::handle_offer(network::IPv4Address from, const protocol::OfferMessage &msg)
{
    add_job(executer_, [this, from, msg](const auto & /*completion_token*/) {
        bool                                  forward = true;
        decltype(ongoing_searches_)::iterator ongoing_search_it;

        auto reply         = std::make_unique<protocol::BasicReply>(msg.message_code);
        reply->request_id  = msg.request_id;
        reply->status_code = protocol::StatusCode::OK;

        {
            std::unique_lock lock {mutex_};
            ongoing_search_it = ongoing_searches_.find(msg.search_id);
            if (ongoing_search_it != ongoing_searches_.end())
            {
                forward = false;
                search_cache_[ongoing_search_it->second.data()->file_hash].emplace(from);
            }
            else
            {
                auto routing_table_it = offer_routing_table_.find(msg.search_id);
                if (routing_table_it == offer_routing_table_.end())
                {
                    lock.unlock();
                    LOG(INFO) << "Routing table entry not found for search_id " << msg.search_id;
                    reply->status_code = protocol::StatusCode::CANNOT_FORWARD;
                    wait_for_reply_confirmation(
                        protocol_message_handler_->send_reply(from, std::move(reply)),
                        msg.request_id);
                    return;
                }

                std::string file_hash = std::get<1>(routing_table_it->second);
                search_cache_[file_hash].emplace(from);
            }
        }

        if (forward)
        {
            forward_offer_message(from, msg);
        }
        else
        {
            // Unpack message
            auto [secret_data, ok] =
                secret_data_interpreter_->decrypt_offer_message(msg.encrypted_data, private_key_);
            if (!ok)
            {
                LOG(WARNING) << "Unable to decrypt secret data of Offer message";
                reply->status_code = protocol::StatusCode::CANNOT_FORWARD;
                wait_for_reply_confirmation(
                    protocol_message_handler_->send_reply(from, std::move(reply)), msg.request_id);
                return;
            }

            add_confirm_tx_routing_table_entry(from, msg.offer_id);

            {
                wait_for_reply_confirmation(
                    protocol_message_handler_->send_reply(from, std::move(reply)), msg.request_id);

                std::lock_guard lock {mutex_};

                // Notify
                listener_group_.notify(&FileLocatorFlowListener::on_file_found,
                    TransferHandle {
                        std::make_shared<TransferHandleImpl>(*ongoing_search_it->second.data(),
                            msg.offer_id, secret_data.transfer_key, secret_data.parts)});
            }

            // Stop search
            cancel_search(ongoing_search_it->second);
        }
    });
}

void FileLocatorFlowImpl::handle_uncache(
    network::IPv4Address from, const protocol::UncacheMessage &msg)
{
    add_job(executer_, [this, from, msg](const auto & /*completion_token*/) {
        {
            std::string file_hash = file_hash_calculator_->encode(msg.file_hash.data());
            if (file_hash.empty())
            {
                LOG(WARNING) << "Cannot decode file hash";
                return;
            }

            std::lock_guard lock {mutex_};

            auto it1 = search_cache_.find(file_hash);
            if (it1 == search_cache_.end())
            {
                LOG(INFO) << "Uncache chain end for file " << file_hash;
                return;
            }

            auto it2 = it1->second.find(from);
            if (it2 == it1->second.end())
            {
                LOG(INFO) << "Uncache chain end for file " << file_hash;
                return;
            }

            it1->second.erase(it2);
            if (it1->second.empty())
            {
                search_cache_.erase(it1);
            }
        }

        // Propagate to all peers
        auto peers_list_future =
            peer_address_provider_->get_peers(peer_address_provider_->get_peers_count());
        add_job(io_executer_, [this, msg,
                                  peers_list_future = std::make_shared<decltype(peers_list_future)>(
                                      std::move(peers_list_future))](const auto &completion_token) {
            peers_list_future->wait();
            if (completion_token.is_cancelled())
            {
                return;
            }

            add_job(executer_, [this, msg, peers_list_future](const auto & /*completion_token*/) {
                auto peers = peers_list_future->get();
                if (peers.empty())
                {
                    return;
                }

                // Send Uncache message
                auto reply_futures = std::make_shared<std::vector<std::pair<network::IPv4Address,
                    std::future<std::unique_ptr<protocol::BasicReply>>>>>();
                reply_futures->reserve(peers.size());
                for (auto peer : peers)
                {
                    auto unique_msg        = std::make_unique<protocol::UncacheMessage>(msg);
                    unique_msg->request_id = rng_.next<protocol::RequestId>();
                    reply_futures->emplace_back(
                        peer, protocol_message_handler_->send(peer, std::move(unique_msg)));
                }

                add_job(io_executer_, [reply_futures](const auto & /*completion_token*/) {
                    for (auto &[a, f] : *reply_futures)
                    {
                        f.wait();
                    }
                });
            });
        });
    });
}

void FileLocatorFlowImpl::handle_confirm_transfer(
    network::IPv4Address from, const protocol::ConfirmTransferMessage &msg)
{
    add_job(executer_, [this, from, msg](const auto & /*completion_token*/) {
        bool           forward = true;
        TransferHandle transfer_handle;

        {
            std::lock_guard lock {mutex_};
            auto            it = sent_offers_.find(msg.offer_id);
            if (it != sent_offers_.end())
            {
                forward         = false;
                transfer_handle = it->second;
                sent_offers_.erase(it);
            }
        }

        if (forward)
        {
            forward_confirm_transfer_message(from, msg);
        }
        else
        {
            auto reply         = std::make_unique<protocol::BasicReply>(msg.message_code);
            reply->request_id  = msg.request_id;
            reply->status_code = protocol::StatusCode::OK;
            wait_for_reply_confirmation(
                protocol_message_handler_->send_reply(from, std::move(reply)), reply->request_id);

            std::lock_guard lock {mutex_};
            confirm_tx_routing_table_.erase(msg.offer_id);
            listener_group_.notify(
                &FileLocatorFlowListener::on_transfer_confirmed, transfer_handle);
        }
    });
}

void FileLocatorFlowImpl::wait_for_reply_confirmation(
    std::future<bool> future, protocol::RequestId msg_id)
{
    auto shared_future = std::make_shared<decltype(future)>(std::move(future));
    add_job(io_executer_, [shared_future, msg_id](const utils::CompletionToken &) {
        bool success = shared_future->get();
        if (!success)
        {
            LOG(WARNING) << "Cannot send reply to message " << msg_id;
        }
    });
}

utils::CompletionToken FileLocatorFlowImpl::add_job(
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

void FileLocatorFlowImpl::forward_search_messsage(
    network::IPv4Address from, const protocol::SearchMessage &msg)
{
    {
        std::lock_guard lock {mutex_};
        if (offer_routing_table_.count(msg.search_id) != 0)
        {
            LOG(INFO) << "Search message propagation loop detected, not forwarding";
            return;
        }
    }

    forward_search_message_loop(from, msg);
}

void FileLocatorFlowImpl::forward_search_message_loop(
    network::IPv4Address from, const protocol::SearchMessage &msg)
{
    auto proceed_with_search = [this](const std::vector<network::IPv4Address> &peers,
                                   const protocol::SearchMessage &msg, network::IPv4Address from) {
        // Send Search message
        auto reply_futures = std::make_shared<std::vector<
            std::pair<network::IPv4Address, std::future<std::unique_ptr<protocol::BasicReply>>>>>();
        reply_futures->reserve(peers.size());
        for (auto peer : peers)
        {
            auto unique_msg        = std::make_unique<protocol::SearchMessage>(msg);
            unique_msg->request_id = rng_.next<protocol::RequestId>();
            reply_futures->emplace_back(
                peer, protocol_message_handler_->send(peer, std::move(unique_msg)));
        }

        add_job(io_executer_, [this, from, msg, reply_futures](const auto &completion_token) {
            // Check replies
            bool success = false;

            for (auto &[a, f] : *reply_futures)
            {
                auto reply = f.get();
                if (completion_token.is_cancelled())
                {
                    return;
                }

                if (reply->status_code == protocol::StatusCode::OK)
                {
                    success = true;
                }
            }

            if (success)
            {
                add_job(executer_, [this, msg, from](const auto & /*completion_token*/) {
                    add_offer_routing_table_entry(
                        from, msg.search_id, file_hash_calculator_->encode(msg.file_hash.data()));
                });
            }
            else
            {
                LOG(WARNING) << "Could not forward Search message";
            }
        });
    };

    std::string file_hash = file_hash_calculator_->encode(msg.file_hash.data());

    bool                              from_cache = false;
    std::vector<network::IPv4Address> cached_peers;

    {
        std::lock_guard lock {mutex_};
        auto            search_cache_it = search_cache_.find(file_hash);
        if (search_cache_it != search_cache_.end() && !search_cache_it->second.empty())
        {
            from_cache = true;
            cached_peers.resize(search_cache_it->second.size());
            std::copy(search_cache_it->second.cbegin(), search_cache_it->second.cend(),
                cached_peers.begin());
        }
    }

    if (!from_cache)
    {
        // Find some peers
        auto peers_list_future = peer_address_provider_->get_peers(search_propagation_degree_);
        add_job(io_executer_, [this, proceed_with_search, from, msg,
                                  peers_list_future = std::make_shared<decltype(peers_list_future)>(
                                      std::move(peers_list_future))](const auto &completion_token) {
            peers_list_future->wait();
            if (completion_token.is_cancelled())
            {
                return;
            }

            add_job(executer_, [this, proceed_with_search, from, msg, peers_list_future](
                                   const auto & /*completion_token*/) {
                auto reply         = std::make_unique<protocol::BasicReply>(msg.message_code);
                reply->request_id  = msg.request_id;
                reply->status_code = protocol::StatusCode::OK;

                auto peers = peers_list_future->get();
                if (peers.empty())
                {
                    LOG(ERROR) << "No peers found";
                    reply->status_code = protocol::StatusCode::CANNOT_FORWARD;
                }

                wait_for_reply_confirmation(
                    protocol_message_handler_->send_reply(from, std::move(reply)), msg.request_id);

                if (peers.empty())
                {
                    return;
                }

                proceed_with_search(peers, msg, from);
            });
        });
    }
    else
    {
        // Send to a random element from cache
        auto peer = cached_peers[rng_.next<size_t>(cached_peers.size() - 1)];

        // Ping the chosen peer
        auto ping        = std::make_unique<protocol::PingMessage>();
        ping->request_id = rng_.next<protocol::RequestId>();

        auto ping_future = protocol_message_handler_->send(peer, std::move(ping));
        add_job(io_executer_, [this, proceed_with_search, peer, msg, from, file_hash,
                                  ping_future = std::make_shared<decltype(ping_future)>(
                                      std::move(ping_future))](const auto &completion_token) {
            ping_future->wait();
            if (completion_token.is_cancelled())
            {
                return;
            }

            add_job(executer_, [this, proceed_with_search, peer, msg, from, file_hash, ping_future](
                                   const auto & /*completion_token*/) {
                auto ping_reply = ping_future->get();
                if (ping_reply->status_code == protocol::StatusCode::OK)
                {
                    proceed_with_search({peer}, msg, from);
                }
                else
                {
                    {
                        std::lock_guard lock {mutex_};
                        search_cache_[file_hash].erase(peer);
                    }
                    forward_search_message_loop(from, msg);

                    auto uncache_msg        = std::make_unique<protocol::UncacheMessage>();
                    uncache_msg->request_id = rng_.next<protocol::RequestId>();
                    uncache_msg->file_hash  = msg.file_hash;
                    auto uncache_future =
                        protocol_message_handler_->send(from, std::move(uncache_msg));

                    add_job(io_executer_,
                        [uncache_future = std::make_shared<decltype(uncache_future)>(
                             std::move(uncache_future))](
                            const auto & /*completion_token*/) { uncache_future->wait(); });
                }
            });
        });
    }
}

void FileLocatorFlowImpl::forward_offer_message(
    network::IPv4Address from, const protocol::OfferMessage &msg)
{
    network::IPv4Address forward_to;
    auto                 reply = std::make_unique<protocol::BasicReply>(msg.message_code);
    reply->request_id          = msg.request_id;
    reply->status_code         = protocol::StatusCode::OK;

    {
        std::lock_guard lock {mutex_};

        auto it = offer_routing_table_.find(msg.search_id);
        if (it == offer_routing_table_.end())
        {
            LOG(INFO) << "Routing table entry not found for search_id " << msg.search_id;
            reply->status_code = protocol::StatusCode::CANNOT_FORWARD;
            wait_for_reply_confirmation(
                protocol_message_handler_->send_reply(from, std::move(reply)), msg.request_id);
            return;
        }

        forward_to = std::get<0>(it->second);
        offer_routing_table_.erase(it);
    }

    wait_for_reply_confirmation(
        protocol_message_handler_->send_reply(from, std::move(reply)), msg.request_id);

    auto new_msg        = std::make_unique<protocol::OfferMessage>(msg);
    new_msg->request_id = rng_.next<protocol::RequestId>();

    auto offer_future = protocol_message_handler_->send(forward_to, std::move(new_msg));
    add_job(io_executer_, [this, from, offer_id = msg.offer_id,
                              offer_future = std::make_shared<decltype(offer_future)>(
                                  std::move(offer_future))](const auto &completion_token) {
        auto reply = offer_future->get();
        if (completion_token.is_cancelled())
        {
            return;
        }

        if (reply->status_code == protocol::StatusCode::OK)
        {
            add_job(executer_, [this, from, offer_id](const auto & /*completion_token*/) {
                add_confirm_tx_routing_table_entry(from, offer_id);
            });
        }
        else
        {
            LOG(WARNING) << "Could not forward Offer message";
        }
    });
}

void FileLocatorFlowImpl::forward_confirm_transfer_message(
    network::IPv4Address from, const protocol::ConfirmTransferMessage &msg)
{
    network::IPv4Address forward_to;
    auto                 reply = std::make_unique<protocol::BasicReply>(msg.message_code);
    reply->request_id          = msg.request_id;
    reply->status_code         = protocol::StatusCode::OK;

    {
        std::unique_lock lock {mutex_};

        auto it = confirm_tx_routing_table_.find(msg.offer_id);
        if (it == confirm_tx_routing_table_.end())
        {
            lock.unlock();
            LOG(INFO) << "Routing table entry not found for offer_id " << msg.offer_id;
            reply->status_code = protocol::StatusCode::CANNOT_FORWARD;
            wait_for_reply_confirmation(
                protocol_message_handler_->send_reply(from, std::move(reply)), msg.request_id);
            return;
        }

        forward_to = it->second;
        confirm_tx_routing_table_.erase(it);
    }

    wait_for_reply_confirmation(
        protocol_message_handler_->send_reply(from, std::move(reply)), msg.request_id);

    auto new_msg        = std::make_unique<protocol::ConfirmTransferMessage>(msg);
    new_msg->request_id = rng_.next<protocol::RequestId>();

    auto reply_future = protocol_message_handler_->send(forward_to, std::move(new_msg));
    add_job(io_executer_, [reply_future = std::make_shared<decltype(reply_future)>(
                               std::move(reply_future))](const auto &completion_token) {
        auto reply = reply_future->get();
        if (completion_token.is_cancelled())
        {
            return;
        }

        if (reply->status_code != protocol::StatusCode::OK)
        {
            LOG(WARNING) << "Could not forward ConfirmTransfer message";
        }
    });
}

void FileLocatorFlowImpl::add_offer_routing_table_entry(
    network::IPv4Address from, protocol::SearchId search_id, const std::string &file_hash)
{
    std::lock_guard lock {mutex_};

    if (!offer_routing_table_.emplace(search_id, std::make_tuple(from, file_hash)).second)
    {
        return;
    }

    if (routing_table_entry_expiration_time_sec_ > 0)
    {
        add_timeout(
            std::chrono::seconds(routing_table_entry_expiration_time_sec_), [this, search_id] {
                LOG(INFO) << "Offer routing table entry expired for search id " << search_id;
                std::lock_guard lock {mutex_};
                offer_routing_table_.erase(search_id);
            });
    }
}

void FileLocatorFlowImpl::add_confirm_tx_routing_table_entry(
    network::IPv4Address from, protocol::OfferId offer_id)
{
    std::lock_guard lock {mutex_};

    if (!confirm_tx_routing_table_.emplace(offer_id, from).second)
    {
        return;
    }

    if (routing_table_entry_expiration_time_sec_ > 0)
    {
        add_timeout(
            std::chrono::seconds(routing_table_entry_expiration_time_sec_), [this, offer_id] {
                LOG(INFO) << "Confirm_tx routing table entry expired for offer id " << offer_id;
                std::lock_guard lock {mutex_};
                confirm_tx_routing_table_.erase(offer_id);
            });
    }
}
}  // namespace sand::flows
