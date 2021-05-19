#include "dnlflowimpl.hpp"

#include <algorithm>
#include <set>
#include <utility>

#include <glog/logging.h>

#include "defer.hpp"
#include "dnlconfig.hpp"
#include "dnlflowlistener.hpp"
#include "executer.hpp"
#include "inboundrequestdispatcher.hpp"
#include "protocolmessagehandler.hpp"

namespace sand::flows
{
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
    , started_ {false}
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

void DNLFlowImpl::start()
{
    if (!started_)
    {
        started_ = true;
        sync_timer_.start(
            std::chrono::milliseconds {sync_period_ms_}, [this] { handle_sync_timer_event(); },
            false);
    }
}

void DNLFlowImpl::stop()
{
    stop_impl();
}

void DNLFlowImpl::stop_impl()
{
    if (started_)
    {
        sync_timer_.stop();
        started_ = false;

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
    }
}

void DNLFlowImpl::handle_pull(network::IPv4Address from, const protocol::PullMessage &msg)
{
    if (!started_)
    {
        LOG(INFO) << "DNLFlow not started. PULL message ignored.";
        return;
    }

    std::lock_guard lock {mutex_};
    running_jobs_.insert(executer_->add_job([this, from, msg](
                                                const utils::CompletionToken &completion_token) {
        DEFER({
            std::lock_guard lock {mutex_};
            running_jobs_.erase(completion_token);
        });

        auto future = pick_nodes(msg.address_count);
        auto msg_id = msg.request_id;

        std::unique_lock lock {mutex_};
        running_jobs_.insert(io_executer_->add_job(
            [this, from, msg_id, future = std::make_shared<decltype(future)>(std::move(future))](
                const utils::CompletionToken &completion_token) {
                DEFER({
                    std::lock_guard lock {mutex_};
                    running_jobs_.erase(completion_token);
                });

                future->wait();
                if (completion_token.is_cancelled())
                {
                    return;
                }

                std::unique_lock lock {mutex_};
                running_jobs_.insert(executer_->add_job(
                    [this, from, msg_id, future](const utils::CompletionToken &completion_token) {
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

                        std::lock_guard lock {mutex_};
                        running_jobs_.erase(completion_token);
                    }));
                lock.unlock();
            }));
        lock.unlock();
    }));
}

void DNLFlowImpl::handle_push(network::IPv4Address from, const protocol::PushMessage &msg)
{
    if (!started_)
    {
        LOG(INFO) << "DNLFlow not started. PUSH message ignored.";
        return;
    }

    std::lock_guard lock {mutex_};
    running_jobs_.insert(
        executer_->add_job([this, from, msg](const utils::CompletionToken &completion_token) {
            {
                std::lock_guard lock {mutex_};
                add_node(from);
            }

            auto reply         = std::make_unique<protocol::BasicReply>(msg.message_code);
            reply->request_id  = msg.request_id;
            reply->status_code = protocol::StatusCode::OK;
            auto future        = protocol_message_handler_->send_reply(from, std::move(reply));
            wait_for_reply_confirmation(std::move(future), msg.request_id);

            std::lock_guard lock {mutex_};
            running_jobs_.erase(completion_token);
        }));
}

void DNLFlowImpl::handle_ping(network::IPv4Address from, const protocol::PingMessage &msg)
{
    if (!started_)
    {
        LOG(INFO) << "DNLFlow not started. PING message ignored.";
        return;
    }

    std::lock_guard lock {mutex_};
    running_jobs_.insert(
        executer_->add_job([this, from, msg](const utils::CompletionToken &completion_token) {
            auto reply         = std::make_unique<protocol::BasicReply>(msg.message_code);
            reply->request_id  = msg.request_id;
            reply->status_code = protocol::StatusCode::OK;
            auto future        = protocol_message_handler_->send_reply(from, std::move(reply));
            wait_for_reply_confirmation(std::move(future), msg.request_id);

            std::lock_guard lock {mutex_};
            running_jobs_.erase(completion_token);
        }));
}

void DNLFlowImpl::handle_bye(network::IPv4Address from, const protocol::ByeMessage & /*msg*/)
{
    if (!started_)
    {
        LOG(INFO) << "DNLFlow not started. BYE message ignored.";
        return;
    }

    std::lock_guard lock {mutex_};
    running_jobs_.insert(
        executer_->add_job([this, from](const utils::CompletionToken &completion_token) {
            std::lock_guard lock {mutex_};
            remove_node(from);
            running_jobs_.erase(completion_token);
        }));
}

void DNLFlowImpl::handle_dnl_sync(network::IPv4Address from, const protocol::DNLSyncMessage &msg)
{
    if (!started_)
    {
        LOG(INFO) << "DNLFlow not started. DNLSYNC message ignored.";
        return;
    }

    std::lock_guard lock {mutex_};
    running_jobs_.insert(
        executer_->add_job([this, from, msg](const utils::CompletionToken &completion_token) {
            {
                std::lock_guard                lock {mutex_};
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
                        add_node(evt.address);
                    }
                    else if (evt.action == Event::REMOVE_ADDRESS)
                    {
                        remove_node(evt.address);
                    }
                }
            }

            auto reply         = std::make_unique<protocol::BasicReply>(msg.message_code);
            reply->request_id  = msg.request_id;
            reply->status_code = protocol::StatusCode::OK;
            auto future        = protocol_message_handler_->send_reply(from, std::move(reply));
            wait_for_reply_confirmation(std::move(future), msg.request_id);

            std::lock_guard lock {mutex_};
            running_jobs_.erase(completion_token);
        }));
}

void DNLFlowImpl::wait_for_reply_confirmation(std::future<bool> future, protocol::RequestId msg_id)
{
    auto            shared_future = std::make_shared<decltype(future)>(std::move(future));
    std::lock_guard lock {mutex_};
    running_jobs_.insert(io_executer_->add_job(
        [this, shared_future, msg_id](const utils::CompletionToken &completion_token) {
            bool success = shared_future->get();
            if (!success)
            {
                LOG(WARNING) << "Cannot send reply to message " << msg_id;
            }
            std::lock_guard lock {mutex_};
            running_jobs_.erase(completion_token);
        }));
}

void DNLFlowImpl::handle_sync_timer_event()
{
    if (!started_)
    {
        LOG(INFO) << "DNLFlow not started. Timer event ignored.";
        return;
    }

    std::lock_guard lock {mutex_};
    running_jobs_.insert(executer_->add_job([this](const utils::CompletionToken &completion_token) {
        DEFER({
            std::lock_guard lock {mutex_};
            running_jobs_.erase(completion_token);
        });

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

        std::unique_lock lock {mutex_};
        running_jobs_.insert(io_executer_->add_job(
            [this, reply_futures](const utils::CompletionToken &completion_token) {
                DEFER({
                    std::lock_guard lock {mutex_};
                    running_jobs_.erase(completion_token);
                });

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
            }));
        lock.unlock();
    }));
}

bool DNLFlowImpl::add_node(network::IPv4Address addr)
{
    auto [it, is_new] = nodes_.emplace(addr, 0);
    if (is_new)
    {
        nodes_vector_.push_back(it->first);
        it->second = nodes_vector_.size() - 1;
        return true;
    }
    else
    {
        return false;
    }
}

bool DNLFlowImpl::remove_node(network::IPv4Address addr)
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
        size_t          total_nodes   = nodes_.size();
        size_t          nodes_to_pick = std::min(ctx->count - ctx->result.size(), total_nodes);

        if (nodes_to_pick == 0)
        {
            ctx->promise.set_value(ctx->result);
            return;
        }

        for (size_t i = 0; i != nodes_to_pick; ++i)
        {
            bool picked;
            do
            {
                picked =
                    candidates.insert(nodes_vector_[rng_.next<size_t>(nodes_vector_.size() - 1)])
                        .second;
            } while (!picked);
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

    std::lock_guard lock {mutex_};
    running_jobs_.insert(io_executer_->add_job(
        [this, ctx, ping_futures](const utils::CompletionToken &completion_token) {
            DEFER({
                std::lock_guard lock {mutex_};
                running_jobs_.erase(completion_token);
            });

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
                    ctx->result.push_back(a);
                }
            }

            if (ctx->result.size() < ctx->count)
            {
                std::lock_guard lock {mutex_};
                running_jobs_.insert(
                    executer_->add_job([this, ctx](const utils::CompletionToken &completion_token) {
                        pick_nodes_loop(ctx);
                        std::lock_guard lock {mutex_};
                        running_jobs_.erase(completion_token);
                    }));
            }
            else
            {
                ctx->promise.set_value(ctx->result);
            }
        }));
}
}  // namespace sand::flows
