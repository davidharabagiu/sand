#include "peermanager.hpp"

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
PeerManager::PeerManager(std::shared_ptr<protocol::ProtocolMessageHandler> protocol_message_handler,
    std::shared_ptr<InboundRequestDispatcher> inbound_request_dispatcher,
    std::shared_ptr<DNLConfig> dnl_config, std::shared_ptr<utils::Executer> executer,
    std::shared_ptr<utils::Executer> io_executer)
    : protocol_message_handler_ {std::move(protocol_message_handler)}
    , inbound_request_dispatcher_ {std::move(inbound_request_dispatcher)}
    , dnl_config_ {std::move(dnl_config)}
    , executer_ {std::move(executer)}
    , io_executer_ {std::move(io_executer)}
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

PeerManager::~PeerManager()
{
    inbound_request_dispatcher_->unset_callback<protocol::PullMessage>();
    inbound_request_dispatcher_->unset_callback<protocol::PushMessage>();
    inbound_request_dispatcher_->unset_callback<protocol::ByeMessage>();
    inbound_request_dispatcher_->unset_callback<protocol::PingMessage>();
}

std::future<std::vector<network::IPv4Address>> PeerManager::get_peers(int count)
{
    auto promise = std::make_shared<std::promise<std::vector<network::IPv4Address>>>();
    auto future  = promise->get_future();

    if (count < 1)
    {
        promise->set_value({});
        return future;
    }

    auto ping_future = ping_peers();
    io_executer_->add_job(
        [this, promise, count = size_t(count),
            ping_future = std::make_shared<decltype(ping_future)>(std::move(ping_future))] {
            ping_future->wait();
            executer_->add_job([this, promise, count] {
                auto peers = pick_peers(count);
                if (peers.size() < count)
                {
                    auto new_peers_future = find_new_peers(count - peers.size());
                    io_executer_->add_job(
                        [this, promise, peers = std::move(peers),
                            new_peers_future = std::make_shared<decltype(new_peers_future)>(
                                std::move(new_peers_future))]() mutable {
                            new_peers_future->wait();
                            executer_->add_job(
                                [promise, new_peers_future, peers = std::move(peers)]() mutable {
                                    auto new_peers = new_peers_future->get();
                                    peers.reserve(peers.size() + new_peers.size());
                                    std::copy(new_peers.cbegin(), new_peers.cend(),
                                        std::back_inserter(peers));
                                    promise->set_value(peers);
                                });
                        });
                }
                else
                {
                    promise->set_value(peers);
                }
            });
        });

    return future;
}

void PeerManager::remove_peer(network::IPv4Address addr)
{
    std::lock_guard lock {mutex_};
    auto            it = std::find(peers_.begin(), peers_.end(), addr);
    if (it != peers_.end())
    {
        peers_.erase(it);
    }
}

void PeerManager::handle_pull(network::IPv4Address from, const protocol::PullMessage &msg)
{
    executer_->add_job([this, from, msg] {
        auto ping_future = ping_peers();
        io_executer_->add_job(
            [this, from, msg,
                ping_future = std::make_shared<decltype(ping_future)>(std::move(ping_future))] {
                ping_future->wait();
                executer_->add_job([this, from, msg] {
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

void PeerManager::handle_push(network::IPv4Address from, const protocol::PushMessage &msg)
{
    executer_->add_job([this, from, msg] {
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

void PeerManager::handle_bye(network::IPv4Address from, const protocol::ByeMessage & /*msg*/)
{
    executer_->add_job([this, from] {
        std::lock_guard lock {mutex_};
        auto            it = std::find(peers_.begin(), peers_.end(), from);
        if (it != peers_.end())
        {
            peers_.erase(it);
        }
    });
}

void PeerManager::handle_ping(network::IPv4Address from, const protocol::PingMessage &msg)
{
    executer_->add_job([this, from, msg] {
        auto reply         = std::make_unique<protocol::BasicReply>(msg.message_code);
        reply->request_id  = msg.request_id;
        reply->status_code = protocol::StatusCode::OK;
        auto future        = protocol_message_handler_->send_reply(from, std::move(reply));
        wait_for_reply_confirmation(std::move(future), msg.request_id);
    });
}

void PeerManager::wait_for_reply_confirmation(std::future<bool> future, protocol::RequestId msg_id)
{
    auto shared_future = std::make_shared<decltype(future)>(std::move(future));
    io_executer_->add_job([shared_future, msg_id] {
        bool success = shared_future->get();
        if (!success)
        {
            LOG(WARNING) << "Cannot send reply to message " << msg_id;
        }
    });
}

std::future<void> PeerManager::ping_peers()
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

    io_executer_->add_job([this, promise, ping_futures, peers = std::move(peers)]() mutable {
        for (auto &[a, f] : *ping_futures)
        {
            f.wait();
        }

        executer_->add_job([this, promise, ping_futures, peers = std::move(peers)]() mutable {
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

std::vector<network::IPv4Address> PeerManager::pick_peers(
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

std::future<std::set<network::IPv4Address>> PeerManager::find_new_peers(size_t count)
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

void PeerManager::find_new_peers_loop(const std::shared_ptr<FindNewPeersContext> &ctx)
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

    io_executer_->add_job(
        [this, ctx,
            reply_future = std::make_shared<decltype(reply_future)>(std::move(reply_future))] {
            auto reply      = reply_future->get();
            auto pull_reply = dynamic_cast<protocol::PullReply *>(reply.get());
            if (pull_reply && pull_reply->status_code == protocol::StatusCode::OK)
            {
                executer_->add_job([this, ctx, pull_reply = *pull_reply] {
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

                    io_executer_->add_job([this, ctx, pull_reply, ping_futures] {
                        for (auto &[a, f] : *ping_futures)
                        {
                            auto reply = f.get();
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
                            executer_->add_job([this, ctx] { find_new_peers_loop(ctx); });
                        }
                        else
                        {
                            ctx->promise.set_value(ctx->new_peers);
                        }
                    });
                });
            }
            else
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
                executer_->add_job([this, ctx] { find_new_peers_loop(ctx); });
            }
        });
}
}  // namespace sand::flows
