#ifndef SAND_FLOWS_FILETRANSFERFLOWIMPL_HPP_
#define SAND_FLOWS_FILETRANSFERFLOWIMPL_HPP_

#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>

#include "address.hpp"
#include "completiontoken.hpp"
#include "executer.hpp"
#include "filestorage.hpp"
#include "filetransferflow.hpp"
#include "filetransferflowlistener.hpp"
#include "listenergroup.hpp"
#include "messages.hpp"
#include "peermanagerflowlistener.hpp"
#include "random.hpp"
#include "temporarydatastorage.hpp"
#include "timer.hpp"

namespace sand::crypto
{
// Forward declarations
class AESCipher;
}  // namespace sand::crypto

namespace sand::protocol
{
// Forward declarations
class ProtocolMessageHandler;
}  // namespace sand::protocol

namespace sand::storage
{
// Forward declarations
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

class FileTransferFlowImpl : public FileTransferFlow
{
public:
    FileTransferFlowImpl(std::shared_ptr<protocol::ProtocolMessageHandler> protocol_message_handler,
        std::shared_ptr<InboundRequestDispatcher>      inbound_request_dispatcher,
        std::shared_ptr<PeerAddressProvider>           peer_address_provider,
        std::shared_ptr<storage::FileStorage>          file_storage,
        std::unique_ptr<storage::FileHashInterpreter>  file_hash_interpreter,
        std::shared_ptr<storage::TemporaryDataStorage> temporary_storage,
        std::shared_ptr<crypto::AESCipher> aes, std::shared_ptr<utils::Executer> executer,
        std::shared_ptr<utils::Executer> io_executer, const config::Config &cfg);

    ~FileTransferFlowImpl() override;

    // From FileTransferFlow
    bool  register_listener(std::shared_ptr<FileTransferFlowListener> listener) override;
    bool  unregister_listener(std::shared_ptr<FileTransferFlowListener> listener) override;
    State state() const override;
    void  start() override;
    void  stop() override;
    std::future<TransferHandle> create_offer(const SearchHandle &search_handle) override;
    bool                        send_file(const TransferHandle &transfer_handle) override;
    bool receive_file(const TransferHandle &transfer_handle, const std::string &file_name) override;
    bool cancel_transfer(const TransferHandle &transfer_handle) override;

private:
    void handle_request_drop_point(
        network::IPv4Address from, const protocol::RequestDropPointMessage &msg);
    void handle_request_lift_proxy(
        network::IPv4Address from, const protocol::RequestLiftProxyMessage &msg);
    void handle_init_upload(network::IPv4Address from, const protocol::InitUploadMessage &msg);
    void handle_upload(network::IPv4Address from, const protocol::UploadMessage &msg);
    void handle_fetch(network::IPv4Address from, const protocol::FetchMessage &msg);
    void handle_init_download(network::IPv4Address from, const protocol::InitDownloadMessage &msg);

    void                   set_state(State new_state);
    void                   stop_impl();
    utils::CompletionToken add_job(
        const std::shared_ptr<utils::Executer> &executer, utils::Executer::Job &&job);
    bool check_if_outbound_transfer_cancelled_and_cleanup(protocol::OfferId offer_id);
    bool check_if_inbound_transfer_cancelled_and_cleanup(protocol::OfferId offer_id);
    void outbound_transfer_cleanup(protocol::OfferId offer_id);
    void inbound_transfer_cleanup(protocol::OfferId offer_id);
    void drop_point_transfer_cleanup(protocol::OfferId offer_id);
    void lift_proxy_tranfer_cleanup(protocol::OfferId offer_id);
    void handle_upload_as_drop_point(network::IPv4Address from, const protocol::UploadMessage &msg);
    void handle_upload_as_lift_proxy(network::IPv4Address from, const protocol::UploadMessage &msg);
    void handle_upload_as_endpoint(network::IPv4Address from, const protocol::UploadMessage &msg);

    template<typename Rep, typename Period>
    std::shared_ptr<utils::Timer> add_timeout(std::chrono::duration<Rep, Period> duration,
        std::function<void()> &&func, bool acquire_mutex = true)
    {
        std::unique_lock lock {mutex_, std::defer_lock};
        if (acquire_mutex)
        {
            lock.lock();
        }
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
        return *it;
    }

private:
    struct CommitedProxyRoleData
    {
        protocol::PartSize            part_size;
        std::shared_ptr<utils::Timer> timeout;
    };

    struct OngoingDropPointTransferData
    {
        network::IPv4Address                  uploader;
        protocol::PartSize                    part_size;
        storage::TemporaryDataStorage::Handle storage_handle;
        bool                                  lift_proxy_connected;
        network::IPv4Address                  lift_proxy;
        protocol::PartSize                    bytes_transferred;
        std::shared_ptr<utils::Timer>         timeout;
    };

    struct OngoingLiftProxyTransferData
    {
        network::IPv4Address          downloader;
        network::IPv4Address          drop_point;
        protocol::PartSize            part_size;
        protocol::PartSize            bytes_transferred;
        std::shared_ptr<utils::Timer> timeout;
    };

    struct InboundTransfer
    {
        using PartData = protocol::OfferMessage::SecretData::PartData;

        std::map<network::IPv4Address, PartData> parts_by_source;
        protocol::FileSize                       file_size;
        protocol::FileSize                       bytes_transferred;
        TransferHandle                           transfer_handle {};
        storage::FileStorage::Handle             file_handle;
        std::shared_ptr<utils::Timer>            timeout;
    };

    const std::shared_ptr<protocol::ProtocolMessageHandler>   protocol_message_handler_;
    const std::shared_ptr<InboundRequestDispatcher>           inbound_request_dispatcher_;
    const std::shared_ptr<PeerAddressProvider>                peer_address_provider_;
    const std::shared_ptr<storage::FileStorage>               file_storage_;
    const std::unique_ptr<storage::FileHashInterpreter>       file_hash_interpreter_;
    const std::shared_ptr<storage::TemporaryDataStorage>      temporary_storage_;
    const std::shared_ptr<crypto::AESCipher>                  aes_;
    const std::shared_ptr<utils::Executer>                    executer_;
    const std::shared_ptr<utils::Executer>                    io_executer_;
    const size_t                                              max_part_size_;
    const size_t                                              max_chunk_size_;
    const size_t                                              max_temp_storage_size_;
    const int                                                 receive_file_timeout_;
    const int                                                 drop_point_request_timeout_;
    const int                                                 lift_proxy_request_timeout_;
    const int                                                 drop_point_transfer_timeout_;
    const int                                                 lift_proxy_transfer_timeout_;
    utils::Random                                             rng_;
    utils::ListenerGroup<FileTransferFlowListener>            listener_group_;
    std::set<utils::CompletionToken>                          running_jobs_;
    std::set<protocol::OfferId>                               outbound_transfers_;
    std::map<protocol::OfferId, InboundTransfer>              inbound_transfers_;
    std::set<protocol::OfferId>                               pending_transfer_cancellations_;
    size_t                                                    commited_temp_storage_;
    std::map<network::IPv4Address, CommitedProxyRoleData>     commited_drop_point_roles_;
    std::map<protocol::OfferId, network::IPv4Address>         pending_lift_proxy_connections_;
    std::map<protocol::OfferId, OngoingDropPointTransferData> ongoing_drop_point_transfers_;
    std::map<network::IPv4Address, CommitedProxyRoleData>     commited_lift_proxy_roles_;
    std::map<protocol::OfferId, OngoingLiftProxyTransferData> ongoing_lift_proxy_transfers_;
    std::set<std::shared_ptr<utils::Timer>>                   timeouts_;
    State                                                     state_;
    mutable std::mutex                                        mutex_;
};
}  // namespace sand::flows

#endif  // SAND_FLOWS_FILETRANSFERFLOWIMPL_HPP_
