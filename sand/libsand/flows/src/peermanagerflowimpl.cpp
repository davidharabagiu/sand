#include "peermanagerflowimpl.hpp"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <utility>

#include <glog/logging.h>

#include "dnlconfig.hpp"
#include "executer.hpp"
#include "inboundrequestdispatcher.hpp"
#include "protocolmessagehandler.hpp"

namespace sand::flows
{
PeerManagerFlowImpl::PeerManagerFlowImpl(
    std::shared_ptr<protocol::ProtocolMessageHandler> protocol_message_handler,
    std::shared_ptr<InboundRequestDispatcher>         inbound_request_dispatcher,
    std::shared_ptr<DNLConfig> dnl_config, std::shared_ptr<utils::Executer> executer,
    std::shared_ptr<utils::Executer> io_executer)
    : protocol_message_handler_ {std::move(protocol_message_handler)}
    , inbound_request_dispatcher_ {std::move(inbound_request_dispatcher)}
    , dnl_config_ {std::move(dnl_config)}
    , executer_ {std::move(executer)}
    , io_executer_ {std::move(io_executer)}
    , started_ {false}
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
    if (!started_)
    {
        started_ = true;
    }
}

void PeerManagerFlowImpl::stop()
{
    stop_impl();
}

void PeerManagerFlowImpl::stop_impl()
{
    if (started_)
    {
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

std::future<std::vector<network::IPv4Address>> PeerManagerFlowImpl::get_peers(int count)
{
    auto promise = std::make_shared<std::promise<std::vector<network::IPv4Address>>>();
    auto future  = promise->get_future();

    if (!started_)
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
                              ping_future = std::make_shared<decltype(ping_future)>(std::move(
                                  ping_future))](const utils::CompletionToken &completion_token) {
        ping_future->wait();
        if (completion_token.is_cancelled())
        {
            promise->set_value({});
            return;
        }

        add_job(executer_, [this, promise, count](const utils::CompletionToken &) {
            auto peers = pick_peers(count);
            if (peers.size() >= count)
            {
                promise->set_value(peers);
                return;
            }

            auto new_peers_future = find_new_peers(count - peers.size());

            add_job(io_executer_,
                [this, promise, peers = std::move(peers),
                    new_peers_future =
                        std::make_shared<decltype(new_peers_future)>(std::move(new_peers_future))](
                    const utils::CompletionToken &completion_token) mutable {
                    new_peers_future->wait();
                    if (completion_token.is_cancelled())
                    {
                        promise->set_value({});
                        return;
                    }

                    add_job(executer_, [promise, new_peers_future, peers = std::move(peers)](
                                           const utils::CompletionToken &) mutable {
                        auto new_peers = new_peers_future->get();
                        peers.reserve(peers.size() + new_peers.size());
                        std::copy(new_peers.cbegin(), new_peers.cend(), std::back_inserter(peers));
                        promise->set_value(peers);
                    });
                });
        });
    });

    return future;
}

void PeerManagerFlowImpl::remove_peer(network::IPv4Address addr)
{
    if (!started_)
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

void PeerManagerFlowImpl::handle_pull(network::IPv4Address from, const protocol::PullMessage &msg)
{
    if (!started_)
    {
        LOG(INFO) << "PeerManagerFlow not started. PULL message ignored.";
        return;
    }

    add_job(executer_, [this, from, msg](const utils::CompletionToken &) {
        auto ping_future = ping_peers();

        add_job(io_executer_,
            [this, from, msg,
                ping_future = std::make_shared<decltype(ping_future)>(std::move(ping_future))](
                const utils::CompletionToken &completion_token) {
                ping_future->wait();
                if (completion_token.is_cancelled())
                {
                    return;
                }

                add_job(executer_, [this, from, msg](const utils::CompletionToken &) {
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
    if (!started_)
    {
        LOG(INFO) << "PeerManagerFlow not started. PUSH message ignored.";
        return;
    }

    add_job(executer_, [this, from, msg](const utils::CompletionToken &) {
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
    if (!started_)
    {
        LOG(INFO) << "PeerManagerFlow not started. BYE message ignored.";
        return;
    }

    add_job(executer_, [this, from](const utils::CompletionToken &) {
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
    if (!started_)
    {
        LOG(INFO) << "PeerManagerFlow not started. PING message ignored.";
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

void PeerManagerFlowImpl::wait_for_reply_confirmation(
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

std::future<void> PeerManagerFlowImpl::ping_peers()
{
    auto promise = std::make_shared<std::promise<void>>();
    auto future  = promise->get_future();

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
                              const utils::CompletionToken &completion_token) mutable {
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
                               const utils::CompletionToken &) mutable {
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
    auto ctx       = std::make_shared<FindNewPeersContext>();
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

    add_job(io_executer_, [this, ctx,
                              reply_future = std::make_shared<decltype(reply_future)>(std::move(
                                  reply_future))](const utils::CompletionToken &completion_token) {
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

        add_job(executer_, [this, ctx, pull_reply = *pull_reply](const utils::CompletionToken &) {
            auto ping_futures = std::make_shared<std::vector<std::pair<network::IPv4Address,
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

                auto ping        = std::make_unique<protocol::PingMessage>();
                ping->request_id = rng_.next<protocol::RequestId>();
                ping_futures->emplace_back(
                    addr, protocol_message_handler_->send(addr, std::move(ping)));
            }

            add_job(io_executer_, [this, ctx, pull_reply, ping_futures](
                                      const utils::CompletionToken &completion_token) {
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
                        if (ctx->new_peers.size() >= ctx->count)
                        {
                            break;
                        }

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

                    add_job(executer_,
                        [this, ctx](const utils::CompletionToken &) { find_new_peers_loop(ctx); });
                }
                else
                {
                    ctx->promise.set_value(ctx->new_peers);
                }
            });
        });
    });
}

void PeerManagerFlowImpl::add_job(
    const std::shared_ptr<utils::Executer> &executer, utils::Executer::Job &&job)
{
    if (!started_)
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
