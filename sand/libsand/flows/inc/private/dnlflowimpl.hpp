#include <atomic>
#include <future>
#include <mutex>
#include <set>
#include <unordered_map>
#include <vector>

#include "address.hpp"
#include "completiontoken.hpp"
#include "dnlflow.hpp"
#include "executer.hpp"
#include "listenergroup.hpp"
#include "messages.hpp"
#include "random.hpp"
#include "timer.hpp"

namespace sand::protocol
{
// Forward declarations
class ProtocolMessageHandler;
}  // namespace sand::protocol

namespace sand::config
{
class Config;
class DNLConfig;
}  // namespace sand::config

namespace sand::flows
{
// Forward declarations
class InboundRequestDispatcher;

class DNLFlowImpl : public DNLFlow
{
public:
    DNLFlowImpl(std::shared_ptr<protocol::ProtocolMessageHandler> protocol_message_handler,
        std::shared_ptr<InboundRequestDispatcher>                 inbound_request_dispatcher,
        std::shared_ptr<config::DNLConfig> dnl_config, std::shared_ptr<utils::Executer> executer,
        std::shared_ptr<utils::Executer> io_executer, const config::Config &cfg);
    ~DNLFlowImpl() override;

    bool                register_listener(std::shared_ptr<DNLFlowListener> listener) override;
    bool                unregister_listener(std::shared_ptr<DNLFlowListener> listener) override;
    [[nodiscard]] State state() const override;
    void                start() override;
    void                stop() override;

private:
    void set_state(State new_state);
    void handle_pull(network::IPv4Address from, const protocol::PullMessage &msg);
    void handle_push(network::IPv4Address from, const protocol::PushMessage &msg);
    void handle_bye(network::IPv4Address from, const protocol::ByeMessage &msg);
    void handle_ping(network::IPv4Address from, const protocol::PingMessage &msg);
    void handle_dnl_sync(network::IPv4Address from, const protocol::DNLSyncMessage &msg);
    void wait_for_reply_confirmation(std::future<bool> future, protocol::RequestId msg_id);
    void handle_sync_timer_event();
    bool add_node(network::IPv4Address addr, bool add_to_events = true);
    bool remove_node(network::IPv4Address addr, bool add_to_events = true);
    std::future<std::vector<network::IPv4Address>> pick_nodes(size_t count);
    void                                           stop_impl();
    void add_job(const std::shared_ptr<utils::Executer> &executer, utils::Executer::Job &&job);

    struct PickNodesContext
    {
        std::set<network::IPv4Address>                  result;
        size_t                                          count;
        std::promise<std::vector<network::IPv4Address>> promise;
    };
    void pick_nodes_loop(const std::shared_ptr<PickNodesContext> &ctx);

    using Event = protocol::DNLSyncMessage::Entry;

    // value = index in nodes_vector_
    std::unordered_map<network::IPv4Address, size_t> nodes_;

    std::vector<network::IPv4Address>                       nodes_vector_;
    std::vector<Event>                                      most_recent_events_;
    const std::shared_ptr<protocol::ProtocolMessageHandler> protocol_message_handler_;
    const std::shared_ptr<InboundRequestDispatcher>         inbound_request_dispatcher_;
    const std::shared_ptr<config::DNLConfig>                dnl_config_;
    const std::shared_ptr<utils::Executer>                  executer_;
    const std::shared_ptr<utils::Executer>                  io_executer_;
    utils::Timer                                            sync_timer_;
    utils::ListenerGroup<DNLFlowListener>                   listener_group_;
    utils::Random                                           rng_;
    std::mutex                                              mutex_;
    std::atomic<State>                                      state_;
    std::set<utils::CompletionToken>                        running_jobs_;
    int                                                     sync_period_ms_;
};
}  // namespace sand::flows
