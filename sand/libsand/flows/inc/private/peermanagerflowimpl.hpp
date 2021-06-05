#ifndef SAND_FLOWS_PEERMANAGERFLOWIMPL_HPP_
#define SAND_FLOWS_PEERMANAGERFLOWIMPL_HPP_

#include <atomic>
#include <memory>
#include <mutex>
#include <set>
#include <vector>

#include "completiontoken.hpp"
#include "executer.hpp"
#include "listenergroup.hpp"
#include "messages.hpp"
#include "peeraddressprovider.hpp"
#include "peermanagerflow.hpp"
#include "peermanagerflowlistener.hpp"
#include "random.hpp"

namespace sand::protocol
{
// Forward declarations
class ProtocolMessageHandler;
}  // namespace sand::protocol

namespace sand::flows
{
// Forward declarations
class InboundRequestDispatcher;
class DNLConfig;

class PeerManagerFlowImpl : public PeerManagerFlow
{
public:
    PeerManagerFlowImpl(std::shared_ptr<protocol::ProtocolMessageHandler> protocol_message_handler,
        std::shared_ptr<InboundRequestDispatcher> inbound_request_dispatcher,
        std::shared_ptr<DNLConfig> dnl_config, std::shared_ptr<utils::Executer> executer,
        std::shared_ptr<utils::Executer> io_executer, int initial_peer_count);
    ~PeerManagerFlowImpl() override;

    std::future<std::vector<network::IPv4Address>> get_peers(
        int count, const std::set<network::IPv4Address> &exclude = {}) override;
    int                 get_peers_count() const override;
    void                remove_peer(network::IPv4Address addr) override;
    void                start() override;
    void                stop() override;
    [[nodiscard]] State state() const override;
    bool register_listener(std::shared_ptr<PeerManagerFlowListener> listener) override;
    bool unregister_listener(std::shared_ptr<PeerManagerFlowListener> listener) override;

private:
    void set_state(State new_state);
    void handle_pull(network::IPv4Address from, const protocol::PullMessage &msg);
    void handle_push(network::IPv4Address from, const protocol::PushMessage &msg);
    void handle_bye(network::IPv4Address from, const protocol::ByeMessage &msg);
    void handle_ping(network::IPv4Address from, const protocol::PingMessage &msg);
    void wait_for_reply_confirmation(std::future<bool> future, protocol::RequestId msg_id);
    std::future<bool> register_to_dnl();
    void              register_to_dnl_loop(const std::shared_ptr<std::promise<bool>> &promise);
    void              say_bye_to_peers();
    std::future<void> ping_peers();
    std::vector<network::IPv4Address> pick_peers(
        size_t count, const std::set<network::IPv4Address> &exclude = {});
    std::future<std::set<network::IPv4Address>> find_new_peers(size_t count);
    void                                        stop_impl();
    void add_job(const std::shared_ptr<utils::Executer> &executer, utils::Executer::Job &&job,
        bool allow_from_any_state = false);

    struct FindNewPeersContext
    {
        std::vector<network::IPv4Address>            peers;
        size_t                                       index = 0;
        size_t                                       count;
        std::set<network::IPv4Address>               new_peers;
        std::promise<std::set<network::IPv4Address>> promise;
    };
    void find_new_peers_loop(const std::shared_ptr<FindNewPeersContext> &ctx);

    const std::shared_ptr<protocol::ProtocolMessageHandler> protocol_message_handler_;
    const std::shared_ptr<InboundRequestDispatcher>         inbound_request_dispatcher_;
    const std::shared_ptr<DNLConfig>                        dnl_config_;
    const std::shared_ptr<utils::Executer>                  executer_;
    const std::shared_ptr<utils::Executer>                  io_executer_;
    const int                                               initial_peer_count_;
    utils::Random                                           rng_;
    std::set<network::IPv4Address>                          peers_;
    std::set<utils::CompletionToken>                        running_jobs_;
    std::atomic<State>                                      state_;
    utils::ListenerGroup<PeerManagerFlowListener>           listener_group_;
    mutable std::mutex                                      mutex_;
};
}  // namespace sand::flows

#endif  // SAND_FLOWS_PEERMANAGERFLOWIMPL_HPP_
