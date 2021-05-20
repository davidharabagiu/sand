#include "peermanagerflowimpl.hpp"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <type_traits>
#include <utility>

#include <glog/logging.h>

#include "dnlconfig.hpp"
#include "executer.hpp"
#include "inboundrequestdispatcher.hpp"
#include "protocolmessagehandler.hpp"

namespace sand::flows
{
namespace
{
const char *to_string(PeerManagerFlow::State state)
{
    switch (state)
    {
        case PeerManagerFlow::State::IDLE: return "IDLE";
        case PeerManagerFlow::State::STARTING: return "STARTING";
        case PeerManagerFlow::State::RUNNING: return "RUNNING";
        case PeerManagerFlow::State::STOPPING: return "STOPPING";
        case PeerManagerFlow::State::ERROR: return "ERROR";
        default: return "INVALID";
    }
}

template<typename T>
std::shared_ptr<std::future<T>> make_shared_future(std::future<T> &&future)
{
    return std::make_shared<std::decay_t<decltype(future)>>(std::move(future));
}
}  // namespace

PeerManagerFlowImpl::PeerManagerFlowImpl(
    std::shared_ptr<protocol::ProtocolMessageHandler> protocol_message_handler,
    std::shared_ptr<InboundRequestDispatcher>         inbound_request_dispatcher,
    std::shared_ptr<DNLConfig> dnl_config, std::shared_ptr<utils::Executer> executer,
    std::shared_ptr<utils::Executer> io_executer, int initial_peer_count)
    : protocol_message_handler_ {std::move(protocol_message_handler)}
    , inbound_request_dispatcher_ {std::move(inbound_request_dispatcher)}
    , dnl_config_ {std::move(dnl_config)}
    , executer_ {std::move(executer)}
    , io_executer_ {std::move(io_executer)}
    , initial_peer_count_ {initial_peer_count}
    , state_ {State::IDLE}
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
}

PeerManagerFlowImpl::~PeerManagerFlowImpl()
{
    inbound_request_dispatcher_->unset_callback<protocol::PullMessage>();
    inbound_request_dispatcher_->unset_callback<protocol::PushMessage>();
    inbound_request_dispatcher_->unset_callback<protocol::ByeMessage>();
    inbound_request_dispatcher_->unset_callback<protocol::PingMessage>();
    stop_impl();
}

void PeerManagerFlowImpl::start()
{
    State state = state_;
    if (state != State::IDLE && state != State::ERROR)
    {
        LOG(WARNING) << "Cannot start PeerManagerFlow from state " << to_string(state);
        return;
    }

    set_state(State::STARTING);

    auto future = register_to_dnl();
    add_job(
        io_executer_,
        [this, future = make_shared_future(std::move(future))](const auto &completion_token) {
            future->wait();
            if (completion_token.is_cancelled())
            {
                LOG(ERROR)
                    << "register_to_dnl task was cancelled, setting PeerManagerFlow to ERROR state";
                set_state(State::ERROR);
                return;
            }
            add_job(
                executer_,
                [this, future](const auto & /*completion_token*/) {
                    if (future->get())
                    {
                        set_state(State::RUNNING);

                        if (initial_peer_count_ <= 0)
                        {
                            return;
                        }

                        auto initial_peer_list_future = get_peers(initial_peer_count_);
                        add_job(io_executer_, [this, future = make_shared_future(
                                                         std::move(initial_peer_list_future))](
                                                  const auto & /*completion_token*/) {
                            future->wait();
                            if (peers_.empty() && initial_peer_count_ > 0)
                            {
                                LOG(WARNING) << "No peers were preloaded. Maybe later some will be "
                                                "available.";
                            }
                            else if (peers_.size() != size_t(initial_peer_count_))
                            {
                                LOG(INFO) << "Preloaded peer list with " << peers_.size()
                                          << " addresses, less than the configured amount ("
                                          << initial_peer_count_ << ")";
                            }
                        });
                    }
                    else
                    {
                        LOG(ERROR) << "No alive DNL node was found, setting PeerManagerFlow to "
                                      "ERROR state";
                        set_state(State::ERROR);
                        return;
                    }
                },
                true);
        },
        true);
}

void PeerManagerFlowImpl::stop()
{
    stop_impl();
}

void PeerManagerFlowImpl::stop_impl()
{
    State state = state_;
    if (state != State::RUNNING)
    {
        LOG(WARNING) << "Cannot stop PeerManagerFlow from state " << to_string(state);
        return;
    }

    set_state(State::STOPPING);

    say_bye_to_peers();

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

    peers_.clear();
    if (!running_jobs_.empty())
    {
        LOG(ERROR) << "Some jobs are still running. This should not happen.";
    }

    set_state(State::IDLE);
}

PeerManagerFlow::State PeerManagerFlowImpl::state() const
{
    return state_;
}

bool PeerManagerFlowImpl::register_listener(std::shared_ptr<PeerManagerFlowListener> listener)
{
    return listener_group_.add(listener);
}

bool PeerManagerFlowImpl::unregister_listener(std::shared_ptr<PeerManagerFlowListener> listener)
{
    return listener_group_.remove(listener);
}

std::future<std::vector<network::IPv4Address>> PeerManagerFlowImpl::get_peers(int count)
{
    auto promise = std::make_shared<std::promise<std::vector<network::IPv4Address>>>();
    auto future  = promise->get_future();

    if (state_ != State::RUNNING)
    {
        LOG(INFO) << "PeerManagerFlow not started. Returning empty list.";
        promise->set_value({});
        return future;
    }

    if (count < 1)
    {
        promise->set_value({});
        return future;
    }

    auto ping_future = ping_peers();

    add_job(io_executer_, [this, promise, count = size_t(count),
                              ping_future = make_shared_future(std::move(ping_future))](
                              const auto &completion_token) {
        ping_future->wait();
        if (completion_token.is_cancelled())
        {
            promise->set_value({});
            return;
        }

        add_job(executer_, [this, promise, count](const auto & /*completion_token*/) {
            auto peers = pick_peers(count);
            if (peers.size() >= count)
            {
                promise->set_value(peers);
                return;
            }

            auto new_peers_future = find_new_peers(count - peers.size());

            add_job(io_executer_,
                [this, promise, count, peers = std::move(peers),
                    new_peers_future = make_shared_future(std::move(new_peers_future))](
                    const auto &completion_token) mutable {
                    new_peers_future->wait();
                    if (completion_token.is_cancelled())
                    {
                        promise->set_value({});
                        return;
                    }

                    add_job(executer_, [promise, new_peers_future, count, peers = std::move(peers)](
                                           const auto & /*completion_token*/) mutable {
                        auto new_peers = new_peers_future->get();
                        peers.reserve(std::min(peers.size() + new_peers.size(), count));
                        std::copy_n(new_peers.cbegin(),
                            std::min(count - peers.size(), new_peers.size()),
                            std::back_inserter(peers));
                        promise->set_value(peers);
                    });
                });
        });
    });

    return future;
}

void PeerManagerFlowImpl::remove_peer(network::IPv4Address addr)
{
    if (state_ != State::RUNNING)
    {
        LOG(INFO) << "PeerManagerFlow not started. Ignoring request.";
        return;
    }

    std::lock_guard lock {mutex_};
    auto            it = std::find(peers_.begin(), peers_.end(), addr);
    if (it != peers_.end())
    {
        peers_.erase(it);
    }
}

void PeerManagerFlowImpl::set_state(State new_state)
{
    if (state_ == new_state)
    {
        return;
    }
    state_ = new_state;
    listener_group_.notify(&PeerManagerFlowListener::on_state_changed, new_state);
}

void PeerManagerFlowImpl::handle_pull(network::IPv4Address from, const protocol::PullMessage &msg)
{
    if (state_ != State::RUNNING)
    {
        LOG(INFO) << "PeerManagerFlow not started. PULL message ignored.";
        return;
    }

    add_job(executer_, [this, from, msg](const auto & /*completion_token*/) {
        auto ping_future = ping_peers();

        add_job(io_executer_,
            [this, from, msg, ping_future = make_shared_future(std::move(ping_future))](
                const auto &completion_token) {
                ping_future->wait();
                if (completion_token.is_cancelled())
                {
                    return;
                }

                add_job(executer_, [this, from, msg](const auto & /*completion_token*/) {
                    auto reply        = std::make_unique<protocol::PullReply>();
                    reply->request_id = msg.request_id;
                    reply->peers      = pick_peers(msg.address_count, {from});
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
                    wait_for_reply_confirmation(std::move(send_reply_future), msg.request_id);
                });
            });
    });
}

void PeerManagerFlowImpl::handle_push(network::IPv4Address from, const protocol::PushMessage &msg)
{
    if (state_ != State::RUNNING)
    {
        LOG(INFO) << "PeerManagerFlow not started. PUSH message ignored.";
        return;
    }

    add_job(executer_, [this, from, msg](const auto & /*completion_token*/) {
        auto reply        = std::make_unique<protocol::BasicReply>(msg.message_code);
        reply->request_id = msg.request_id;

        {
            std::lock_guard lock {mutex_};
            peers_.insert(from);
            reply->status_code = protocol::StatusCode::OK;
        }

        auto future = protocol_message_handler_->send_reply(from, std::move(reply));
        wait_for_reply_confirmation(std::move(future), msg.request_id);
    });
}

void PeerManagerFlowImpl::handle_bye(
    network::IPv4Address from, const protocol::ByeMessage & /*msg*/)
{
    if (state_ != State::RUNNING)
    {
        LOG(INFO) << "PeerManagerFlow not started. BYE message ignored.";
        return;
    }

    add_job(executer_, [this, from](const auto & /*completion_token*/) {
        std::lock_guard lock {mutex_};
        auto            it = std::find(peers_.begin(), peers_.end(), from);
        if (it != peers_.end())
        {
            peers_.erase(it);
        }
    });
}

void PeerManagerFlowImpl::handle_ping(network::IPv4Address from, const protocol::PingMessage &msg)
{
    if (state_ != State::RUNNING)
    {
        LOG(INFO) << "PeerManagerFlow not started. PING message ignored.";
        return;
    }

    add_job(executer_, [this, from, msg](const auto & /*completion_token*/) {
        auto reply         = std::make_unique<protocol::BasicReply>(msg.message_code);
        reply->request_id  = msg.request_id;
        reply->status_code = protocol::StatusCode::OK;
        auto future        = protocol_message_handler_->send_reply(from, std::move(reply));
        wait_for_reply_confirmation(std::move(future), msg.request_id);
    });
}

void PeerManagerFlowImpl::wait_for_reply_confirmation(
    std::future<bool> future, protocol::RequestId msg_id)
{
    auto shared_future = make_shared_future(std::move(future));

    add_job(io_executer_, [shared_future, msg_id](const auto & /*completion_token*/) {
        bool success = shared_future->get();
        if (!success)
        {
            LOG(WARNING) << "Cannot send reply to message " << msg_id;
        }
    });
}

std::future<bool> PeerManagerFlowImpl::register_to_dnl()
{
    auto promise = std::make_shared<std::promise<bool>>();
    auto future  = promise->get_future();

    if (state_ != State::STARTING)
    {
        LOG(WARNING)
            << "PeerManagerFlow needs to be in STARTING state in order to perform this operation";
        promise->set_value(false);
        return future;
    }

    register_to_dnl_loop(promise);

    return future;
}

void PeerManagerFlowImpl::register_to_dnl_loop(const std::shared_ptr<std::promise<bool>> &promise)
{
    auto address = dnl_config_->random_pick();
    if (!address)
    {
        promise->set_value(false);
        return;
    }
    auto push        = std::make_unique<protocol::PushMessage>();
    push->request_id = rng_.next<protocol::RequestId>();
    auto push_future = protocol_message_handler_->send(address, std::move(push));

    add_job(
        io_executer_,
        [this, promise, address, push_future = make_shared_future(std::move(push_future))](
            const auto &completion_token) {
            push_future->wait();
            if (completion_token.is_cancelled())
            {
                promise->set_value(false);
                return;
            }
            add_job(
                executer_,
                [this, promise, address, push_future](const auto & /*completion_token*/) {
                    auto reply = push_future->get();
                    if (reply->status_code == protocol::StatusCode::OK)
                    {
                        promise->set_value(true);
                        return;
                    }
                    dnl_config_->exclude(address);
                    register_to_dnl_loop(promise);
                },
                true);
        },
        true);
}

void PeerManagerFlowImpl::say_bye_to_peers()
{
    if (state_ != State::STOPPING)
    {
        LOG(WARNING)
            << "PeerManagerFlow needs to be in STOPPING state in order to perform this operation";
        return;
    }

    for (network::IPv4Address addr : peers_)
    {
        auto bye        = std::make_unique<protocol::ByeMessage>();
        bye->request_id = rng_.next<protocol::RequestId>();
        protocol_message_handler_->send(addr, std::move(bye));
    }
}

std::future<void> PeerManagerFlowImpl::ping_peers()
{
    auto promise = std::make_shared<std::promise<void>>();
    auto future  = promise->get_future();

    if (state_ != State::RUNNING)
    {
        LOG(WARNING)
            << "PeerManagerFlow needs to be in RUNNING state in order to perform this operation";
        promise->set_value();
        return future;
    }

    std::unique_lock               lock {mutex_};
    std::set<network::IPv4Address> peers = peers_;
    lock.unlock();

    auto ping_futures = std::make_shared<std::vector<
        std::pair<network::IPv4Address, std::future<std::unique_ptr<protocol::BasicReply>>>>>();

    for (auto addr : peers)
    {
        auto ping        = std::make_unique<protocol::PingMessage>();
        ping->request_id = rng_.next<protocol::RequestId>();
        ping_futures->emplace_back(addr, protocol_message_handler_->send(addr, std::move(ping)));
    }

    add_job(io_executer_, [this, promise, ping_futures, peers = std::move(peers)](
                              const auto &completion_token) mutable {
        for (auto &[a, f] : *ping_futures)
        {
            f.wait();
            if (completion_token.is_cancelled())
            {
                promise->set_value();
                return;
            }
        }

        add_job(executer_, [this, promise, ping_futures, peers = std::move(peers)](
                               const auto & /*completion_token*/) mutable {
            for (auto &[a, f] : *ping_futures)
            {
                if (f.get()->status_code != protocol::StatusCode::OK)
                {
                    peers.erase(a);
                }
            }

            {
                std::lock_guard lock {mutex_};
                peers_ = peers;
            }

            promise->set_value();
        });
    });

    return future;
}

std::vector<network::IPv4Address> PeerManagerFlowImpl::pick_peers(
    size_t count, const std::set<network::IPv4Address> &exclude)
{
    std::set<network::IPv4Address>    choice;
    std::vector<network::IPv4Address> selection_pool;

    {
        std::lock_guard lock {mutex_};

        // Get selection pool
        selection_pool.reserve(peers_.size() - exclude.size());
        std::copy_if(peers_.cbegin(), peers_.cend(), std::back_inserter(selection_pool),
            [&exclude](auto addr) { return exclude.count(addr) == 0; });
    }

    // Cap number of requested peers
    count = std::min(count, selection_pool.size());

    // If number of peers is invalid, return empty list
    if (count <= 0)
    {
        return {};
    }

    // Random pick
    for (size_t i = 0; i != count; ++i)
    {
        network::IPv4Address addr;
        do
        {
            addr = selection_pool[rng_.next<size_t>(selection_pool.size() - 1)];
        } while (choice.count(addr) != 0);
        choice.insert(addr);
    }

    return std::vector<network::IPv4Address>(choice.cbegin(), choice.cend());
}

std::future<std::set<network::IPv4Address>> PeerManagerFlowImpl::find_new_peers(size_t count)
{
    auto ctx = std::make_shared<FindNewPeersContext>();

    if (state_ != State::RUNNING)
    {
        LOG(WARNING)
            << "PeerManagerFlow needs to be in RUNNING state in order to perform this operation";
        ctx->promise.set_value({});
        return ctx->promise.get_future();
    }

    auto dnl_nodes = dnl_config_->get_all();

    // Add current peers to PULL msg destinations
    std::unique_lock lock {mutex_};
    ctx->peers.reserve(peers_.size() + dnl_nodes.size());
    std::copy(peers_.cbegin(), peers_.cend(), std::back_inserter(ctx->peers));
    lock.unlock();
    rng_.shuffle(ctx->peers.begin(), ctx->peers.end());

    // Add DNL nodes to PULL msg destinations
    auto it_dnl_begin = ctx->peers.end();
    std::copy(dnl_nodes.cbegin(), dnl_nodes.cend(), std::back_inserter(ctx->peers));
    rng_.shuffle(it_dnl_begin, ctx->peers.end());

    ctx->count = count;
    find_new_peers_loop(ctx);

    return ctx->promise.get_future();
}

void PeerManagerFlowImpl::find_new_peers_loop(const std::shared_ptr<FindNewPeersContext> &ctx)
{
    if (ctx->index >= ctx->peers.size())
    {
        ctx->promise.set_value(ctx->new_peers);
        return;
    }

    auto msg           = std::make_unique<protocol::PullMessage>();
    msg->request_id    = rng_.next<protocol::RequestId>();
    msg->address_count = decltype(msg->address_count)(std::min(ctx->count - ctx->new_peers.size(),
        size_t(std::numeric_limits<decltype(msg->address_count)>::max())));
    auto reply_future  = protocol_message_handler_->send(ctx->peers[ctx->index], std::move(msg));

    add_job(io_executer_, [this, ctx, reply_future = make_shared_future(std::move(reply_future))](
                              const auto &completion_token) {
        auto reply = reply_future->get();
        if (completion_token.is_cancelled())
        {
            ctx->promise.set_value({});
            return;
        }

        auto pull_reply = dynamic_cast<protocol::PullReply *>(reply.get());
        if (!pull_reply || pull_reply->status_code != protocol::StatusCode::OK)
        {
            if (!pull_reply)
            {
                LOG(WARNING) << "Cannot interpret reply as PullReply";
            }
            else
            {
                LOG(INFO) << "Peer " << network::conversion::to_string(ctx->peers[ctx->index])
                          << " did not respond to PULL";
            }

            ++ctx->index;

            add_job(executer_,
                [this, ctx](const utils::CompletionToken &) { find_new_peers_loop(ctx); });

            return;
        }

        add_job(
            executer_, [this, ctx, pull_reply = *pull_reply](const auto & /*completion_token*/) {
                auto push_futures = std::make_shared<std::vector<std::pair<network::IPv4Address,
                    std::future<std::unique_ptr<protocol::BasicReply>>>>>();
                for (auto addr : pull_reply.peers)
                {
                    bool address_already_present = false;
                    {
                        std::lock_guard lock {mutex_};
                        address_already_present = peers_.count(addr) != 0;
                    }
                    if (address_already_present)
                    {
                        continue;
                    }

                    auto push        = std::make_unique<protocol::PushMessage>();
                    push->request_id = rng_.next<protocol::RequestId>();
                    push_futures->emplace_back(
                        addr, protocol_message_handler_->send(addr, std::move(push)));
                }

                add_job(io_executer_,
                    [this, ctx, pull_reply, push_futures](const auto &completion_token) {
                        for (auto &[a, f] : *push_futures)
                        {
                            auto reply = f.get();

                            if (completion_token.is_cancelled())
                            {
                                ctx->promise.set_value({});
                                return;
                            }

                            if (reply->status_code == protocol::StatusCode::OK)
                            {
                                std::lock_guard lock {mutex_};
                                if (peers_.insert(a).second)
                                {
                                    ctx->new_peers.insert(a);
                                }
                            }
                        }

                        if (ctx->new_peers.size() < ctx->count)
                        {
                            ++ctx->index;

                            add_job(executer_, [this, ctx](const utils::CompletionToken &) {
                                find_new_peers_loop(ctx);
                            });
                        }
                        else
                        {
                            ctx->promise.set_value(ctx->new_peers);
                        }
                    });
            });
    });
}

void PeerManagerFlowImpl::add_job(const std::shared_ptr<utils::Executer> &executer,
    utils::Executer::Job &&job, bool allow_from_any_state)
{
    if (!allow_from_any_state && state_ != State::RUNNING)
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
