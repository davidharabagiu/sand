#ifndef SAND_FLOWS_FILETRANSFERFLOWIMPL_HPP_
#define SAND_FLOWS_FILETRANSFERFLOWIMPL_HPP_

#include <memory>

#include "address.hpp"
#include "filetransferflow.hpp"
#include "filetransferflowlistener.hpp"
#include "listenergroup.hpp"
#include "messages.hpp"
#include "peermanagerflowlistener.hpp"

namespace sand::utils
{
// Forward declarations
class Executer;
}  // namespace sand::utils

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
}  // namespace sand::storage

namespace sand::flows
{
// Forward declarations
class InboundRequestDispatcher;
class PeerManagerFlow;

class FileTransferFlowImpl
    : public FileTransferFlow
    , public PeerManagerFlowListener
    , public std::enable_shared_from_this<FileTransferFlowImpl>
{
public:
    FileTransferFlowImpl(std::shared_ptr<protocol::ProtocolMessageHandler> protocol_message_handler,
        std::shared_ptr<InboundRequestDispatcher> inbound_request_dispatcher,
        std::shared_ptr<PeerManagerFlow>          peer_address_provider,
        std::shared_ptr<storage::FileStorage> file_storage, std::shared_ptr<crypto::AESCipher> aes,
        std::shared_ptr<utils::Executer> executer, std::shared_ptr<utils::Executer> io_executer);

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

    // From PeerManagerFlowListener
    void on_state_changed(PeerManagerFlow::State new_state) override;
    void on_peer_disconnected(network::IPv4Address address) override;

private:
    void handle_request_proxy(network::IPv4Address from, const protocol::RequestProxyMessage &msg);
    void handle_init_upload(network::IPv4Address from, const protocol::InitUploadMessage &msg);
    void handle_upload(network::IPv4Address from, const protocol::UploadMessage &msg);
    void handle_fetch(network::IPv4Address from, const protocol::FetchMessage &msg);
    void handle_init_download(network::IPv4Address from, const protocol::InitDownloadMessage &msg);

private:
    const std::shared_ptr<protocol::ProtocolMessageHandler> protocol_message_handler_;
    const std::shared_ptr<InboundRequestDispatcher>         inbound_request_dispatcher_;
    const std::shared_ptr<PeerManagerFlow>                  peer_address_provider_;
    const std::shared_ptr<storage::FileStorage>             file_storage_;
    const std::shared_ptr<crypto::AESCipher>                aes_;
    const std::shared_ptr<utils::Executer>                  executer_;
    const std::shared_ptr<utils::Executer>                  io_executer_;
    utils::ListenerGroup<FileTransferFlowListener>          listener_group_;
};
}  // namespace sand::flows

#endif  // SAND_FLOWS_FILETRANSFERFLOWIMPL_HPP_
