#ifndef SAND_FLOWS_FILETRANSFERFLOWIMPL_HPP_
#define SAND_FLOWS_FILETRANSFERFLOWIMPL_HPP_

#include <memory>
#include <mutex>
#include <set>

#include "address.hpp"
#include "completiontoken.hpp"
#include "executer.hpp"
#include "filetransferflow.hpp"
#include "filetransferflowlistener.hpp"
#include "listenergroup.hpp"
#include "messages.hpp"
#include "peermanagerflowlistener.hpp"
#include "random.hpp"

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
class FileStorage;
class FileHashInterpreter;
}  // namespace sand::storage

namespace sand::flows
{
// Forward declarations
class InboundRequestDispatcher;
class PeerAddressProvider;

class FileTransferFlowImpl
    : public FileTransferFlow
    , public std::enable_shared_from_this<FileTransferFlowImpl>
{
public:
    FileTransferFlowImpl(std::shared_ptr<protocol::ProtocolMessageHandler> protocol_message_handler,
        std::shared_ptr<InboundRequestDispatcher>     inbound_request_dispatcher,
        std::shared_ptr<PeerAddressProvider>          peer_address_provider,
        std::shared_ptr<storage::FileStorage>         file_storage,
        std::shared_ptr<storage::FileHashInterpreter> file_hash_interpreter,
        std::shared_ptr<crypto::AESCipher> aes, std::shared_ptr<utils::Executer> executer,
        std::shared_ptr<utils::Executer> io_executer, size_t max_part_size, size_t max_chunk_size);

    ~FileTransferFlowImpl() override;

    // From FileTransferFlow
    bool  register_listener(std::shared_ptr<FileTransferFlowListener> listener) override;
    bool  unregister_listener(std::shared_ptr<FileTransferFlowListener> listener) override;
    State state() const override;
    void  start() override;
    void  stop() override;
    std::future<TransferHandle> create_offer(const SearchHandle &search_handle) override;
    bool                        send_file(const TransferHandle &transfer_handle) override;
    bool                        receive_file(const TransferHandle &transfer_handle) override;
    bool                        cancel_transfer(const TransferHandle &transfer_handle) override;

private:
    void handle_request_proxy(network::IPv4Address from, const protocol::RequestProxyMessage &msg);
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

private:
    const std::shared_ptr<protocol::ProtocolMessageHandler> protocol_message_handler_;
    const std::shared_ptr<InboundRequestDispatcher>         inbound_request_dispatcher_;
    const std::shared_ptr<PeerAddressProvider>              peer_address_provider_;
    const std::shared_ptr<storage::FileStorage>             file_storage_;
    const std::shared_ptr<storage::FileHashInterpreter>     file_hash_interpreter_;
    const std::shared_ptr<crypto::AESCipher>                aes_;
    const std::shared_ptr<utils::Executer>                  executer_;
    const std::shared_ptr<utils::Executer>                  io_executer_;
    const size_t                                            max_part_size_;
    const size_t                                            max_chunk_size_;
    utils::Random                                           rng_;
    utils::ListenerGroup<FileTransferFlowListener>          listener_group_;
    std::set<utils::CompletionToken>                        running_jobs_;
    std::set<protocol::OfferId>                             outbound_transfers_;
    std::set<protocol::OfferId>                             inbound_transfers_;
    std::set<protocol::OfferId>                             pending_transfer_cancellations_;
    State                                                   state_;
    mutable std::mutex                                      mutex_;
};
}  // namespace sand::flows

#endif  // SAND_FLOWS_FILETRANSFERFLOWIMPL_HPP_
