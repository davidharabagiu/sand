#ifndef SAND_FLOWS_PEERMANAGERIMPL_HPP_
#define SAND_FLOWS_PEERMANAGERIMPL_HPP_

#include <memory>
#include <mutex>
#include <set>
#include <vector>

#include "completiontoken.hpp"
#include "messages.hpp"
#include "peeraddressprovider.hpp"
#include "random.hpp"

namespace sand::protocol
{
// Forward declarations
class ProtocolMessageHandler;
}  // namespace sand::protocol

namespace sand::utils
{
// Forward declarations
class Executer;
}  // namespace sand::utils

namespace sand::flows
{
// Forward declarations
class InboundRequestDispatcher;
class DNLConfig;

class PeerManagerFlowImpl : public PeerAddressProvider
{
public:
    PeerManagerFlowImpl(std::shared_ptr<protocol::ProtocolMessageHandler> protocol_message_handler,
        std::shared_ptr<InboundRequestDispatcher> inbound_request_dispatcher,
        std::shared_ptr<DNLConfig> dnl_config, std::shared_ptr<utils::Executer> executer,
        std::shared_ptr<utils::Executer> io_executer);
    ~PeerManagerFlowImpl() override;

    std::future<std::vector<network::IPv4Address>> get_peers(int count) override;
    void                                           remove_peer(network::IPv4Address addr) override;

private:
    void handle_pull(network::IPv4Address from, const protocol::PullMessage &msg);
    void handle_push(network::IPv4Address from, const protocol::PushMessage &msg);
    void handle_bye(network::IPv4Address from, const protocol::ByeMessage &msg);
    void handle_ping(network::IPv4Address from, const protocol::PingMessage &msg);
    void wait_for_reply_confirmation(std::future<bool> future, protocol::RequestId msg_id);
    std::future<void>                 ping_peers();
    std::vector<network::IPv4Address> pick_peers(
        size_t count, const std::set<network::IPv4Address> &exclude = {});
    std::future<std::set<network::IPv4Address>> find_new_peers(size_t count);

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
    utils::Random                                           rng_;
    std::set<network::IPv4Address>                          peers_;
    std::set<utils::CompletionToken>                        running_jobs_;
    std::mutex                                              mutex_;
};
}  // namespace sand::flows

#endif  // SAND_FLOWS_PEERMANAGERIMPL_HPP_
