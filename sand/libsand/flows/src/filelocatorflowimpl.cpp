#include "filelocatorflowimpl.hpp"

#include <tuple>

#include <glog/logging.h>

#include "filehashcalculator.hpp"
#include "filestorage.hpp"
#include "inboundrequestdispatcher.hpp"
#include "peeraddressprovider.hpp"
#include "protocolmessagehandler.hpp"
#include "searchhandleimpl.hpp"

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
    std::shared_ptr<utils::Executer> executer, std::shared_ptr<utils::Executer> io_executer,
    std::string public_key, std::string private_key, int search_propagation_degree,
    int search_timeout_sec, int routing_table_entry_expiration_time_sec)
    : protocol_message_handler_ {std::move(protocol_message_handler)}
    , inbound_request_dispatcher_ {std::move(inbound_request_dispatcher)}
    , peer_address_provider_ {std::move(peer_address_provider)}
    , file_storage_ {std::move(file_storage)}
    , file_hash_calculator_ {std::move(file_hash_calculator)}
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
    std::unique_lock lock {mutex_};

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

    lock.unlock();

    // Prepare Search message
    protocol::SearchMessage msg;
    msg.search_id         = rng_.next<protocol::SearchId>();
    msg.sender_public_key = public_key_;
    if (file_hash_calculator_->decode(file_hash, msg.file_hash.data()))
    {
        LOG(WARNING) << "Invalid file hash provided";
        return SearchHandle();
    }

    // Create SearchHandle
    auto search_handle_data       = std::make_shared<SearchHandleImpl>();
    search_handle_data->file_hash = file_hash;
    search_handle_data->search_id = msg.search_id;
    SearchHandle search_handle(search_handle_data);

    // Find some peers
    auto peers_list_future = peer_address_provider_->get_peers(search_propagation_degree_);
    auto completion_token =
        add_job(io_executer_, [this, msg, search_handle,
                                  peers_list_future = std::make_shared<decltype(peers_list_future)>(
                                      std::move(peers_list_future))](const auto &completion_token) {
            peers_list_future->wait();
            if (completion_token.is_cancelled())
            {
                return;
            }

            add_job(executer_, [this, msg, search_handle, peers_list_future](
                                   const auto & /*completion_token*/) {
                auto peers = peers_list_future->get();
                if (peers.empty())
                {
                    LOG(ERROR) << "No peers found";
                    std::lock_guard lock {mutex_};
                    listener_group_.notify(&FileLocatorFlowListener::on_file_search_error,
                        search_handle, "Internal error");
                    return;
                }

                // Send Search message
                auto reply_futures = std::make_shared<std::vector<std::pair<network::IPv4Address,
                    std::future<std::unique_ptr<protocol::BasicReply>>>>>();
                reply_futures->reserve(peers.size());
                for (auto peer : peers)
                {
                    auto unique_msg        = std::make_unique<protocol::SearchMessage>(msg);
                    unique_msg->request_id = rng_.next<protocol::RequestId>();
                    reply_futures->emplace_back(
                        peer, protocol_message_handler_->send(peer, std::move(unique_msg)));
                }

                add_job(io_executer_,
                    [this, search_handle, reply_futures](const auto &completion_token) {
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
                            else
                            {
                                LOG(INFO) << "Peer " << network::conversion::to_string(a)
                                          << " is not responding";
                                peer_address_provider_->remove_peer(a);
                            }
                        }

                        if (!success)
                        {
                            LOG(ERROR) << "No peer is responding.";
                            std::lock_guard lock {mutex_};
                            ongoing_searches_.erase(search_handle.data()->search_id);
                            ongoing_searches_files_.erase(search_handle.data()->file_hash);
                            listener_group_.notify(&FileLocatorFlowListener::on_file_search_error,
                                search_handle, "No peer responded, please try again");
                        }
                    });
            });
        });

    lock.lock();

    auto [it, ok] = ongoing_searches_.emplace(search_handle.data()->search_id,
        OngoingSearch {search_handle,
            search_timeout_sec_ > 0 ? std::make_unique<utils::Timer>(io_executer_) : nullptr});
    if (!ok)
    {
        completion_token.cancel();
        LOG(ERROR) << "Cannot insert SearchHandle in ongoing_searches set";
        return SearchHandle();
    }

    std::tie(std::ignore, ok) = ongoing_searches_files_.insert(file_hash);
    if (!ok)
    {
        completion_token.cancel();
        LOG(ERROR) << "Cannot insert File hash in ongoing_searches_files set";
        ongoing_searches_.erase(it);
        return SearchHandle();
    }

    if (search_timeout_sec_ > 0)
    {
        // Set search timeout
        it->second.expire_timer->start(
            std::chrono::seconds(search_timeout_sec_),
            [this, search_handle] {
                add_job(executer_, [this, search_handle](const auto & /*completion_token*/) {
                    LOG(INFO) << "Search timeout reached. Abandoning operation.";
                    std::lock_guard lock {mutex_};
                    ongoing_searches_.erase(search_handle.data()->search_id);
                    ongoing_searches_files_.erase(search_handle.data()->file_hash);
                    listener_group_.notify(
                        &FileLocatorFlowListener::on_file_search_error, search_handle, "Timeout");
                });
            },
            true);
    }

    return search_handle;
}

bool FileLocatorFlowImpl::cancel_search(const SearchHandle &search_handle)
{
    bool ok = ongoing_searches_.erase(search_handle.data()->search_id) != 0;
    ok &= ongoing_searches_files_.erase(search_handle.data()->file_hash) != 0;
    return ok;
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
            auto sh_data       = std::make_shared<SearchHandleImpl>();
            sh_data->file_hash = file_hash;
            sh_data->search_id = msg.search_id;

            std::lock_guard lock {mutex_};
            listener_group_.notify(
                &FileLocatorFlowListener::on_file_wanted, SearchHandle {sh_data});
        }
    });
}

void FileLocatorFlowImpl::handle_offer(network::IPv4Address from, const protocol::OfferMessage &msg)
{
    add_job(executer_, [this, from, msg](const auto & /*completion_token*/) {
        bool         forward = true;
        SearchHandle search_handle;

        {
            std::lock_guard lock {mutex_};
            auto            it = ongoing_searches_.find(msg.search_id);
            if (it != ongoing_searches_.end())
            {
                forward                        = false;
                search_handle                  = it->second.search_handle.clone();
                search_handle.data()->offer_id = msg.offer_id;

                {
                    auto [it2, ok] = received_offers_.emplace(
                        msg.offer_id, ReceivedOffer {msg.search_id, from,
                                          std::make_unique<utils::Timer>(io_executer_)});

                    if (!ok)
                    {
                        LOG(WARNING) << "Route entry duplication";
                    }
                    else
                    {
                        it2->second.expire_timer->start(
                            std::chrono::seconds(routing_table_entry_expiration_time_sec_),
                            [this, offer_id = msg.offer_id] {
                                add_job(
                                    executer_, [this, offer_id](const auto & /*completion_token*/) {
                                        std::lock_guard lock {mutex_};
                                        received_offers_.erase(offer_id);
                                    });
                            },
                            true);
                    }
                }
            }
        }

        if (forward)
        {
            forward_offer_message(from, msg);
        }
        else
        {
            std::lock_guard lock {mutex_};
            listener_group_.notify(&FileLocatorFlowListener::on_file_found, search_handle);
        }
    });
}

void FileLocatorFlowImpl::handle_uncache(
    network::IPv4Address /*from*/, const protocol::UncacheMessage & /*msg*/)
{
}

void FileLocatorFlowImpl::handle_confirm_transfer(
    network::IPv4Address from, const protocol::ConfirmTransferMessage &msg)
{
    add_job(executer_, [this, from, msg](const auto & /*completion_token*/) {
        bool         forward = true;
        SearchHandle search_handle;

        {
            std::lock_guard lock {mutex_};
            auto            it = sent_offers_.find(msg.offer_id);
            if (it != ongoing_searches_.end())
            {
                forward       = false;
                search_handle = it->second.search_handle;
                sent_offers_.erase(it);
            }
        }

        if (forward)
        {
            forward_confirm_transfer_message(from, msg);
        }
        else
        {
            std::lock_guard lock {mutex_};
            listener_group_.notify(&FileLocatorFlowListener::on_transfer_confirmed, search_handle);
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
    // Find some peers
    auto peers_list_future = peer_address_provider_->get_peers(search_propagation_degree_);
    auto completion_token =
        add_job(io_executer_, [this, from, msg,
                                  peers_list_future = std::make_shared<decltype(peers_list_future)>(
                                      std::move(peers_list_future))](const auto &completion_token) {
            peers_list_future->wait();
            if (completion_token.is_cancelled())
            {
                return;
            }

            add_job(executer_, [this, from, msg, peers_list_future](
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

                // Send Search message
                auto reply_futures = std::make_shared<std::vector<std::pair<network::IPv4Address,
                    std::future<std::unique_ptr<protocol::BasicReply>>>>>();
                reply_futures->reserve(peers.size());
                for (auto peer : peers)
                {
                    auto unique_msg        = std::make_unique<protocol::SearchMessage>(msg);
                    unique_msg->request_id = rng_.next<protocol::RequestId>();
                    reply_futures->emplace_back(
                        peer, protocol_message_handler_->send(peer, std::move(unique_msg)));
                }

                add_job(
                    io_executer_, [this, from, msg, reply_futures](const auto &completion_token) {
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
                            std::lock_guard lock {mutex_};

                            auto [it, ok] = routing_table_.emplace(msg.search_id,
                                RouteNode {from, std::make_unique<utils::Timer>(io_executer_)});
                            if (!ok)
                            {
                                LOG(WARNING) << "Route entry duplication";
                            }
                            else
                            {
                                it->second.expire_timer->start(
                                    std::chrono::seconds(routing_table_entry_expiration_time_sec_),
                                    [this, search_id = msg.search_id] {
                                        add_job(executer_,
                                            [this, search_id](const auto & /*completion_token*/) {
                                                std::lock_guard lock {mutex_};
                                                routing_table_.erase(search_id);
                                            });
                                    },
                                    true);
                            }
                        }
                    });
            });
        });
}

void FileLocatorFlowImpl::forward_offer_message(
    network::IPv4Address from, const protocol::OfferMessage &msg)
{
    network::IPv4Address forward_to = 0;
    auto                 reply      = std::make_unique<protocol::BasicReply>(msg.message_code);
    reply->request_id               = msg.request_id;
    reply->status_code              = protocol::StatusCode::OK;

    do
    {
        std::lock_guard lock {mutex_};

        auto it = routing_table_.find(msg.search_id);
        if (it == routing_table_.end())
        {
            LOG(INFO) << "Routing table entry not found for search_id " << msg.search_id;
            reply->status_code = protocol::StatusCode::CANNOT_FORWARD;
            break;
        }

        forward_to = it->second.from;
    } while (false);

    wait_for_reply_confirmation(
        protocol_message_handler_->send_reply(from, std::move(reply)), msg.request_id);

    if (forward_to == 0)
    {
        return;
    }

    {
        std::lock_guard lock {mutex_};
        auto [it, ok] = reverse_routing_table_.emplace(
            msg.offer_id, RouteNode {from, std::make_unique<utils::Timer>(io_executer_)});
        if (!ok)
        {
            LOG(WARNING) << "Reverse route entry duplication";
            return;
        }

        it->second.expire_timer->start(
            std::chrono::seconds(routing_table_entry_expiration_time_sec_),
            [this, offer_id = msg.offer_id] {
                add_job(executer_, [this, offer_id](const auto & /*completion_token*/) {
                    std::lock_guard lock {mutex_};
                    reverse_routing_table_.erase(offer_id);
                });
            },
            true);
    }

    auto new_msg        = std::make_unique<protocol::OfferMessage>(msg);
    new_msg->request_id = rng_.next<protocol::RequestId>();

    auto offer_future = protocol_message_handler_->send(forward_to, std::move(new_msg));
    add_job(io_executer_,
        [offer_future = std::make_shared<decltype(offer_future)>(std::move(offer_future))](
            const auto & /*completion_token*/) { offer_future->wait(); });
}

void FileLocatorFlowImpl::forward_confirm_transfer_message(
    network::IPv4Address from, const protocol::ConfirmTransferMessage &msg)
{
    network::IPv4Address forward_to = 0;
    auto                 reply      = std::make_unique<protocol::BasicReply>(msg.message_code);
    reply->request_id               = msg.request_id;
    reply->status_code              = protocol::StatusCode::OK;

    do
    {
        std::lock_guard lock {mutex_};

        auto it = reverse_routing_table_.find(msg.offer_id);
        if (it == routing_table_.end())
        {
            LOG(INFO) << "Reverse routing table entry not found for offer_id " << msg.offer_id;
            reply->status_code = protocol::StatusCode::CANNOT_FORWARD;
            break;
        }

        forward_to = it->second.from;

        reverse_routing_table_.erase(it);
    } while (false);

    wait_for_reply_confirmation(
        protocol_message_handler_->send_reply(from, std::move(reply)), msg.request_id);

    if (forward_to == 0)
    {
        return;
    }

    auto new_msg        = std::make_unique<protocol::ConfirmTransferMessage>(msg);
    new_msg->request_id = rng_.next<protocol::RequestId>();

    auto future = protocol_message_handler_->send(forward_to, std::move(new_msg));
    add_job(io_executer_, [future = std::make_shared<decltype(future)>(std::move(future))](
                              const auto & /*completion_token*/) { future->wait(); });
}
}  // namespace sand::flows