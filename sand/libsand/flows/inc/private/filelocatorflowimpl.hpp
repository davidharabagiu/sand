#ifndef SAND_FLOWS_FILELOCATORFLOWIMPL_HPP_
#define SAND_FLOWS_FILELOCATORFLOWIMPL_HPP_

#include <atomic>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>

#include "completiontoken.hpp"
#include "executer.hpp"
#include "filelocatorflow.hpp"
#include "filelocatorflowlistener.hpp"
#include "listenergroup.hpp"
#include "messages.hpp"
#include "random.hpp"
#include "timer.hpp"

namespace sand::protocol
{
// Forward declarations
class ProtocolMessageHandler;
class SecretDataInterpreter;
}  // namespace sand::protocol

namespace sand::storage
{
// Forward declarations
class FileStorage;
class FileHashInterpreter;
}  // namespace sand::storage

namespace sand::config
{
// Forward declarations
class Config;
}  // namespace sand::config

namespace sand::flows
{
// Forward declarations
class InboundRequestDispatcher;
class PeerAddressProvider;

class FileLocatorFlowImpl : public FileLocatorFlow
{
public:
    FileLocatorFlowImpl(std::shared_ptr<protocol::ProtocolMessageHandler> protocol_message_handler,
        std::shared_ptr<InboundRequestDispatcher>        inbound_request_dispatcher,
        std::shared_ptr<PeerAddressProvider>             peer_address_provider,
        std::shared_ptr<storage::FileStorage>            file_storage,
        std::unique_ptr<storage::FileHashInterpreter>    file_hash_interpreter,
        std::shared_ptr<protocol::SecretDataInterpreter> secret_data_interpreter,
        std::shared_ptr<utils::Executer> executer, std::shared_ptr<utils::Executer> io_executer,
        std::string public_key, std::string private_key, const config::Config &cfg);

    ~FileLocatorFlowImpl() override;

    bool register_listener(std::shared_ptr<FileLocatorFlowListener> listener) override;
    bool unregister_listener(std::shared_ptr<FileLocatorFlowListener> listener) override;
    [[nodiscard]] State        state() const override;
    void                       start() override;
    void                       stop() override;
    [[nodiscard]] SearchHandle search(const std::string &file_hash) override;
    bool                       cancel_search(const SearchHandle &search_handle) override;
    bool                       send_offer(const TransferHandle &transfer_handle) override;
    bool                       cancel_offer(const TransferHandle &transfer_handle) override;
    bool                       confirm_transfer(const TransferHandle &transfer_handle) override;

private:
    void search_loop(const protocol::SearchMessage &msg, const SearchHandle &search_handle);

    void set_state(State new_state);
    void handle_search(network::IPv4Address from, const protocol::SearchMessage &msg);
    void handle_offer(network::IPv4Address from, const protocol::OfferMessage &msg);
    void handle_uncache(network::IPv4Address from, const protocol::UncacheMessage &msg);
    void handle_confirm_transfer(
        network::IPv4Address from, const protocol::ConfirmTransferMessage &msg);
    void wait_for_reply_confirmation(std::future<bool> future, protocol::RequestId msg_id);
    void stop_impl();
    utils::CompletionToken add_job(
        const std::shared_ptr<utils::Executer> &executer, utils::Executer::Job &&job);

    template<typename Rep, typename Period>
    void add_timeout(std::chrono::duration<Rep, Period> duration, std::function<void()> &&func)
    {
        std::lock_guard               lock {mutex_};
        decltype(timeouts_)::iterator it;
        std::tie(it, std::ignore) = timeouts_.emplace(std::make_shared<utils::Timer>(io_executer_));
        (*it)->start(std::chrono::duration_cast<utils::Timer::Period>(duration),
            [this, timer = std::weak_ptr<utils::Timer>(*it), func = std::move(func)] {
                add_job(executer_, [this, timer, func](const auto & /*completion_token*/) {
                    func();
                    std::lock_guard lock {mutex_};
                    timeouts_.erase(timer.lock());
                });
            });
    }

    void forward_search_messsage(network::IPv4Address from, const protocol::SearchMessage &msg);
    void forward_search_message_loop(network::IPv4Address from, const protocol::SearchMessage &msg);
    void forward_offer_message(network::IPv4Address from, const protocol::OfferMessage &msg);
    void forward_confirm_transfer_message(
        network::IPv4Address from, const protocol::ConfirmTransferMessage &msg);

    void add_offer_routing_table_entry(
        network::IPv4Address from, protocol::SearchId search_id, const std::string &file_hash);
    void add_confirm_tx_routing_table_entry(network::IPv4Address from, protocol::OfferId offer_id);

    std::map<protocol::SearchId, SearchHandle>  ongoing_searches_;
    std::set<std::string>                       ongoing_searches_files_;
    std::map<protocol::OfferId, TransferHandle> sent_offers_;

    std::map<protocol::SearchId, std::tuple<network::IPv4Address, std::string>>
                                                      offer_routing_table_;
    std::map<protocol::OfferId, network::IPv4Address> confirm_tx_routing_table_;

#ifdef ENABLE_EXPERIMENTAL_SEARCH_CACHE
    std::map<std::string, std::set<network::IPv4Address>> search_cache_;
#endif  // ENABLE_EXPERIMENTAL_SEARCH_CACHE

    std::set<std::shared_ptr<utils::Timer>> timeouts_;

    const std::shared_ptr<protocol::ProtocolMessageHandler> protocol_message_handler_;
    const std::shared_ptr<InboundRequestDispatcher>         inbound_request_dispatcher_;
    const std::shared_ptr<PeerAddressProvider>              peer_address_provider_;
    const std::shared_ptr<storage::FileStorage>             file_storage_;
    const std::unique_ptr<storage::FileHashInterpreter>     file_hash_interpreter_;
    const std::shared_ptr<protocol::SecretDataInterpreter>  secret_data_interpreter_;
    const std::shared_ptr<utils::Executer>                  executer_;
    const std::shared_ptr<utils::Executer>                  io_executer_;
    const std::string                                       public_key_;
    const std::string                                       private_key_;
    const int                                               search_propagation_degree_;
    const int                                               search_timeout_sec_;
    const uint8_t                                           search_message_initial_ttl_;
    const int                                     routing_table_entry_expiration_time_sec_;
    utils::ListenerGroup<FileLocatorFlowListener> listener_group_;
    utils::Random                                 rng_;
    std::set<utils::CompletionToken>              running_jobs_;
    std::atomic<State>                            state_;
    std::mutex                                    mutex_;
};
}  // namespace sand::flows

#endif  // SAND_FLOWS_FILELOCATORFLOWIMPL_HPP_
