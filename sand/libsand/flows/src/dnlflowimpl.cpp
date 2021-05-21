#include "dnlflowimpl.hpp"

#include <algorithm>
#include <set>
#include <utility>

#include <glog/logging.h>

#include "dnlconfig.hpp"
#include "dnlflowlistener.hpp"
#include "inboundrequestdispatcher.hpp"
#include "protocolmessagehandler.hpp"

namespace sand::flows
{
namespace
{
const char *to_string(DNLFlow::State state)
{
    switch (state)
    {
        case DNLFlow::State::IDLE: return "IDLE";
        case DNLFlow::State::RUNNING: return "RUNNING";
        case DNLFlow::State::STOPPING: return "STOPPING";
        default: return "INVALID_STATE";
    }
}
}  // namespace

DNLFlowImpl::DNLFlowImpl(std::shared_ptr<protocol::ProtocolMessageHandler> protocol_message_handler,
    std::shared_ptr<InboundRequestDispatcher> inbound_request_dispatcher,
    std::shared_ptr<DNLConfig> dnl_config, std::shared_ptr<utils::Executer> executer,
    std::shared_ptr<utils::Executer> io_executer, int sync_period_ms)
    : protocol_message_handler_ {std::move(protocol_message_handler)}
    , inbound_request_dispatcher_ {std::move(inbound_request_dispatcher)}
    , dnl_config_ {std::move(dnl_config)}
    , executer_ {std::move(executer)}
    , io_executer_ {std::move(io_executer)}
    , sync_timer_ {io_executer_}
    , state_ {State::IDLE}
    , sync_period_ms_ {sync_period_ms}
{
    inbound_request_dispatcher_->set_callback<protocol::PullMessage>([this](auto &&p1, auto &&p2) {
        handle_pull(std::forward<decltype(p1)>(p1), std::forward<decltype(p2)>(p2));
    });
    inbound_request_dispatcher_->set_callback<protocol::PushMessage>([this](auto &&p1, auto &&p2) {
        handle_push(std::forward<decltype(p1)>(p1), std::forward<decltype(p2)>(p2));
    });
    inbound_request_dispatcher_->set_callback<protocol::ByeMessage>([this](auto &&p1, auto &&p2) {
        handle_bye(std::forward<decltype(p1)>(p1), std::forward<decltype(p2)>(p2));
    });
    inbound_request_dispatcher_->set_callback<protocol::PingMessage>([this](auto &&p1, auto &&p2) {
        handle_ping(std::forward<decltype(p1)>(p1), std::forward<decltype(p2)>(p2));
    });
    inbound_request_dispatcher_->set_callback<protocol::DNLSyncMessage>(
        [this](auto &&p1, auto &&p2) {
            handle_dnl_sync(std::forward<decltype(p1)>(p1), std::forward<decltype(p2)>(p2));
        });
}

DNLFlowImpl::~DNLFlowImpl()
{
    inbound_request_dispatcher_->unset_callback<protocol::PullMessage>();
    inbound_request_dispatcher_->unset_callback<protocol::PushMessage>();
    inbound_request_dispatcher_->unset_callback<protocol::ByeMessage>();
    inbound_request_dispatcher_->unset_callback<protocol::PingMessage>();
    inbound_request_dispatcher_->unset_callback<protocol::DNLSyncMessage>();
    stop_impl();
}

bool DNLFlowImpl::register_listener(std::shared_ptr<DNLFlowListener> listener)
{
    return listener_group_.add(listener);
}

bool DNLFlowImpl::unregister_listener(std::shared_ptr<DNLFlowListener> listener)
{
    return listener_group_.remove(listener);
}

DNLFlow::State DNLFlowImpl::state() const
{
    return state_;
}

void DNLFlowImpl::start()
{
    State state = state_;

    if (state != State::IDLE)
    {
        LOG(WARNING) << "DNLFlow cannot be started from state " << to_string(state);
        return;
    }

    if (sync_period_ms_ > 0)
    {
        sync_timer_.start(
            std::chrono::milliseconds {sync_period_ms_}, [this] { handle_sync_timer_event(); },
            false);
    }

    set_state(State::RUNNING);
}

void DNLFlowImpl::stop()
{
    stop_impl();
}

void DNLFlowImpl::stop_impl()
{
    State state = state_;

    if (state != State::RUNNING)
    {
        LOG(WARNING) << "DNLFlow cannot be started from state " << to_string(state);
        return;
    }

    set_state(State::STOPPING);

    sync_timer_.stop();

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
    nodes_.clear();
    nodes_vector_.clear();
    most_recent_events_.clear();

    set_state(State::IDLE);
}

void DNLFlowImpl::set_state(State new_state)
{
    if (state_ == new_state)
    {
        return;
    }
    state_ = new_state;
    listener_group_.notify(&DNLFlowListener::on_state_changed, new_state);
}

void DNLFlowImpl::handle_pull(network::IPv4Address from, const protocol::PullMessage &msg)
{
    if (state_ != State::RUNNING)
    {
        LOG(INFO) << "DNLFlow not started. PULL message ignored.";
        return;
    }

    add_job(executer_, [this, from, msg](const utils::CompletionToken &) {
        auto future = pick_nodes(msg.address_count);
        auto msg_id = msg.request_id;

        add_job(io_executer_,
            [this, from, msg_id, future = std::make_shared<decltype(future)>(std::move(future))](
                const utils::CompletionToken &completion_token) {
                future->wait();
                if (completion_token.is_cancelled())
                {
                    return;
                }

                add_job(executer_, [this, from, msg_id, future](const utils::CompletionToken &) {
                    auto reply         = std::make_unique<protocol::PullReply>();
                    reply->request_id  = msg_id;
                    reply->status_code = protocol::StatusCode::OK;
                    reply->peers       = future->get();
                    if (reply->peers.empty())
                    {
                        reply->status_code = protocol::StatusCode::RESOURCE_NOT_AVAILABLE;
                    }
                    else
                    {
                        reply->status_code = protocol::StatusCode::OK;
                    }

                    auto send_reply_future =
                        protocol_message_handler_->send_reply(from, std::move(reply));
                    wait_for_reply_confirmation(std::move(send_reply_future), msg_id);
                });
            });
    });
}

void DNLFlowImpl::handle_push(network::IPv4Address from, const protocol::PushMessage &msg)
{
    if (state_ != State::RUNNING)
    {
        LOG(INFO) << "DNLFlow not started. PUSH message ignored.";
        return;
    }

    add_job(executer_, [this, from, msg](const utils::CompletionToken &) {
        bool success;

        {
            std::lock_guard lock {mutex_};
            success = add_node(from);
        }

        auto reply         = std::make_unique<protocol::BasicReply>(msg.message_code);
        reply->request_id  = msg.request_id;
        reply->status_code = success ? protocol::StatusCode::OK : protocol::StatusCode::DUPLICATION;
        auto future        = protocol_message_handler_->send_reply(from, std::move(reply));
        wait_for_reply_confirmation(std::move(future), msg.request_id);
    });
}

void DNLFlowImpl::handle_ping(network::IPv4Address from, const protocol::PingMessage &msg)
{
    if (state_ != State::RUNNING)
    {
        LOG(INFO) << "DNLFlow not started. PING message ignored.";
        return;
    }

    add_job(executer_, [this, from, msg](const utils::CompletionToken &) {
        auto reply         = std::make_unique<protocol::BasicReply>(msg.message_code);
        reply->request_id  = msg.request_id;
        reply->status_code = protocol::StatusCode::OK;
        auto future        = protocol_message_handler_->send_reply(from, std::move(reply));
        wait_for_reply_confirmation(std::move(future), msg.request_id);
    });
}

void DNLFlowImpl::handle_bye(network::IPv4Address from, const protocol::ByeMessage & /*msg*/)
{
    if (state_ != State::RUNNING)
    {
        LOG(INFO) << "DNLFlow not started. BYE message ignored.";
        return;
    }

    add_job(executer_, [this, from](const utils::CompletionToken &) {
        std::lock_guard lock {mutex_};
        remove_node(from);
    });
}

void DNLFlowImpl::handle_dnl_sync(network::IPv4Address from, const protocol::DNLSyncMessage &msg)
{
    if (state_ != State::RUNNING)
    {
        LOG(INFO) << "DNLFlow not started. DNLSYNC message ignored.";
        return;
    }

    add_job(executer_, [this, from, msg](const utils::CompletionToken &) {
        auto reply        = std::make_unique<protocol::BasicReply>(msg.message_code);
        reply->request_id = msg.request_id;

        {
            std::unique_lock lock {mutex_};
            if (!dnl_config_->contains(from))
            {
                LOG(INFO) << "DNLSync message source not in DNL configuration. Ignoring message.";

                lock.unlock();
                reply->status_code = protocol::StatusCode::FOREIGN_DNL_ADDRESS;
                auto future        = protocol_message_handler_->send_reply(from, std::move(reply));
                wait_for_reply_confirmation(std::move(future), msg.request_id);

                return;
            }

            std::vector<Event>             inversed_merged_events;
            std::set<network::IPv4Address> marked_nodes;

            for (size_t i = msg.entries.size() - 1, j = most_recent_events_.size() - 1,
                        index_limit = static_cast<size_t>(-1);
                 i != index_limit || j != index_limit;)
            {
                const Event *evt;

                if (i == index_limit)
                {
                    evt = &most_recent_events_[j--];
                }
                else if (j == index_limit)
                {
                    evt = &msg.entries[i--];
                }
                else if (msg.entries[i].timestamp > most_recent_events_[j].timestamp)
                {
                    evt = &msg.entries[i--];
                }
                else
                {
                    evt = &most_recent_events_[j--];
                }

                if (!marked_nodes.insert(evt->address).second)
                {
                    continue;
                }
                inversed_merged_events.push_back(*evt);
            }

            most_recent_events_.resize(inversed_merged_events.size());
            std::copy(inversed_merged_events.crbegin(), inversed_merged_events.crend(),
                most_recent_events_.begin());

            for (const auto &evt : most_recent_events_)
            {
                if (evt.action == Event::ADD_ADDRESS)
                {
                    add_node(evt.address, false);
                }
                else if (evt.action == Event::REMOVE_ADDRESS)
                {
                    remove_node(evt.address, false);
                }
            }

            if (sync_period_ms_ <= 0)
            {
                most_recent_events_.clear();
            }
        }

        reply->status_code = protocol::StatusCode::OK;
        auto future        = protocol_message_handler_->send_reply(from, std::move(reply));
        wait_for_reply_confirmation(std::move(future), msg.request_id);
    });
}

void DNLFlowImpl::wait_for_reply_confirmation(std::future<bool> future, protocol::RequestId msg_id)
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

void DNLFlowImpl::handle_sync_timer_event()
{
    if (state_ != State::RUNNING)
    {
        LOG(INFO) << "DNLFlow not started. Timer event ignored.";
        return;
    }

    {
        std::lock_guard lock {mutex_};
        if (most_recent_events_.empty())
        {
            return;
        }
    }

    add_job(executer_, [this](const utils::CompletionToken &) {
        auto msg        = std::make_unique<protocol::DNLSyncMessage>();
        msg->request_id = rng_.next<protocol::RequestId>();
        {
            std::lock_guard lock {mutex_};
            msg->entries = std::move(most_recent_events_);
            most_recent_events_.clear();
        }

        auto other_dnl_nodes = dnl_config_->get_all();
        auto reply_futures   = std::make_shared<std::vector<
            std::pair<network::IPv4Address, std::future<std::unique_ptr<protocol::BasicReply>>>>>();
        for (auto addr : other_dnl_nodes)
        {
            reply_futures->emplace_back(
                addr, protocol_message_handler_->send(
                          addr, std::make_unique<protocol::DNLSyncMessage>(*msg)));
        }

        add_job(io_executer_, [reply_futures](const utils::CompletionToken &completion_token) {
            for (auto &[a, f] : *reply_futures)
            {
                auto reply = f.get();
                if (completion_token.is_cancelled())
                {
                    return;
                }

                if (reply->status_code != protocol::StatusCode::OK)
                {
                    LOG(INFO) << "DNL node " << network::conversion::to_string(a)
                              << " does not respond";
                }
            }
        });
    });
}

bool DNLFlowImpl::add_node(network::IPv4Address addr, bool add_to_events)
{
    auto [it, is_new] = nodes_.emplace(addr, 0);
    if (is_new)
    {
        nodes_vector_.push_back(it->first);
        it->second = nodes_vector_.size() - 1;

        if (sync_period_ms_ > 0 && add_to_events)
        {
            most_recent_events_.push_back(
                {std::chrono::system_clock::now(), addr, Event::ADD_ADDRESS});
        }

        listener_group_.notify(&DNLFlowListener::on_node_connected, addr);
        return true;
    }
    else
    {
        return false;
    }
}

bool DNLFlowImpl::remove_node(network::IPv4Address addr, bool add_to_events)
{
    auto it = nodes_.find(addr);
    if (it == nodes_.end())
    {
        return false;
    }

    size_t               idx           = it->second;
    size_t               last_idx      = nodes_vector_.size() - 1;
    network::IPv4Address last_idx_addr = nodes_vector_[last_idx];
    nodes_vector_[idx]                 = nodes_vector_[last_idx];
    nodes_[last_idx_addr]              = idx;
    nodes_vector_.resize(last_idx);
    nodes_.erase(it);

    if (sync_period_ms_ > 0 && add_to_events)
    {
        most_recent_events_.push_back(
            {std::chrono::system_clock::now(), addr, Event::REMOVE_ADDRESS});
    }

    listener_group_.notify(&DNLFlowListener::on_node_disconnected, addr);

    return true;
}

std::future<std::vector<network::IPv4Address>> DNLFlowImpl::pick_nodes(size_t count)
{
    auto ctx   = std::make_shared<PickNodesContext>();
    ctx->count = count;
    pick_nodes_loop(ctx);

    return ctx->promise.get_future();
}

void DNLFlowImpl::pick_nodes_loop(const std::shared_ptr<PickNodesContext> &ctx)
{
    std::set<network::IPv4Address> candidates;

    {
        std::lock_guard lock {mutex_};
        size_t          total_nodes = nodes_.size();
        size_t          nodes_to_pick =
            std::min(ctx->count - ctx->result.size(), total_nodes - ctx->result.size());

        if (nodes_to_pick == 0)
        {
            ctx->promise.set_value(
                std::vector<network::IPv4Address>(ctx->result.cbegin(), ctx->result.cend()));
            return;
        }

        for (size_t i = 0; i != nodes_to_pick; ++i)
        {
            network::IPv4Address pick;
            do
            {
                pick = nodes_vector_[rng_.next<size_t>(nodes_vector_.size() - 1)];
            } while (candidates.count(pick) != 0 || ctx->result.count(pick) != 0);
            candidates.insert(pick);
        }
    }

    auto ping_futures = std::make_shared<std::vector<
        std::pair<network::IPv4Address, std::future<std::unique_ptr<protocol::BasicReply>>>>>();
    for (auto addr : candidates)
    {
        auto ping        = std::make_unique<protocol::PingMessage>();
        ping->request_id = rng_.next<protocol::RequestId>();
        ping_futures->emplace_back(addr, protocol_message_handler_->send(addr, std::move(ping)));
    }

    add_job(
        io_executer_, [this, ctx, ping_futures](const utils::CompletionToken &completion_token) {
            for (auto &[a, f] : *ping_futures)
            {
                auto reply = f.get();
                if (completion_token.is_cancelled())
                {
                    ctx->promise.set_value({});
                    return;
                }

                if (reply->status_code == protocol::StatusCode::OK)
                {
                    ctx->result.insert(a);
                }
                else
                {
                    remove_node(a);
                }
            }

            if (ctx->result.size() < ctx->count)
            {
                add_job(executer_,
                    [this, ctx](const utils::CompletionToken &) { pick_nodes_loop(ctx); });
            }
            else
            {
                ctx->promise.set_value(
                    std::vector<network::IPv4Address>(ctx->result.cbegin(), ctx->result.cend()));
            }
        });
}

void DNLFlowImpl::add_job(
    const std::shared_ptr<utils::Executer> &executer, utils::Executer::Job &&job)
{
    if (state_ != State::RUNNING)
    {
        return;
    }

    std::lock_guard lock {mutex_};
    running_jobs_.insert(executer->add_job(
        [this, job = std::move(job)](const utils::CompletionToken &completion_token) {
            job(completion_token);
            std::lock_guard lock {mutex_};
            running_jobs_.erase(completion_token);
        }));
}
}  // namespace sand::flows
