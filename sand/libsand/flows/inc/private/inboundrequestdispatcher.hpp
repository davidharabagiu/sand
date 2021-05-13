#ifndef SAND_FLOWS_INBOUNDREQUESTDISPATCHER_HPP_
#define SAND_FLOWS_INBOUNDREQUESTDISPATCHER_HPP_

#include <any>
#include <functional>
#include <map>
#include <memory>
#include <type_traits>
#include <typeindex>
#include <typeinfo>

#include "protocolmessagelistener.hpp"

namespace sand::protocol
{
// Forward declarations
class ProtocolMessageHandler;
}  // namespace sand::protocol

namespace sand::flows
{
class InboundRequestDispatcher
    : public protocol::ProtocolMessageListener
    , public std::enable_shared_from_this<InboundRequestDispatcher>
{
public:
    template<typename M>
    using Callback = std::function<void(network::IPv4Address, const M &)>;

    explicit InboundRequestDispatcher(
        std::shared_ptr<protocol::ProtocolMessageHandler> protocol_message_handler);

    void initialize();
    void uninitialize();

    template<typename M>
    auto set_callback(Callback<M> &&callback)
        -> std::enable_if_t<std::is_base_of_v<protocol::Message, M> &&
                            !std::is_base_of_v<protocol::BasicReply, M>>
    {
        callbacks_[typeid(M)] = std::move(callback);
    }

    template<typename M>
    auto unset_callback() -> std::enable_if_t<std::is_base_of_v<protocol::Message, M> &&
                                              !std::is_base_of_v<protocol::BasicReply, M>>
    {
        callbacks_.erase(typeid(M));
    }

    void on_message_received(
        network::IPv4Address from, const protocol::PullMessage &message) override;
    void on_message_received(
        network::IPv4Address from, const protocol::PushMessage &message) override;
    void on_message_received(
        network::IPv4Address from, const protocol::ByeMessage &message) override;
    void on_message_received(
        network::IPv4Address from, const protocol::DeadMessage &message) override;
    void on_message_received(
        network::IPv4Address from, const protocol::PingMessage &message) override;
    void on_message_received(
        network::IPv4Address from, const protocol::DNLSyncMessage &message) override;
    void on_message_received(
        network::IPv4Address from, const protocol::SearchMessage &message) override;
    void on_message_received(
        network::IPv4Address from, const protocol::OfferMessage &message) override;
    void on_message_received(
        network::IPv4Address from, const protocol::UncacheMessage &message) override;
    void on_message_received(
        network::IPv4Address from, const protocol::ConfirmTransferMessage &message) override;
    void on_message_received(
        network::IPv4Address from, const protocol::RequestProxyMessage &message) override;
    void on_message_received(
        network::IPv4Address from, const protocol::InitUploadMessage &message) override;
    void on_message_received(
        network::IPv4Address from, const protocol::UploadMessage &message) override;
    void on_message_received(
        network::IPv4Address from, const protocol::FetchMessage &message) override;
    void on_message_received(
        network::IPv4Address from, const protocol::InitDownloadMessage &message) override;

private:
    template<typename M>
    auto dispatch(network::IPv4Address from, const M &message)
        -> std::enable_if_t<std::is_base_of_v<protocol::Message, M> &&
                            !std::is_base_of_v<protocol::BasicReply, M>>
    {
        auto it = callbacks_.find(typeid(M));
        if (it != callbacks_.end())
        {
            std::any_cast<Callback<M>>(it->second)(from, message);
        }
    }

    std::shared_ptr<protocol::ProtocolMessageHandler> protocol_message_handler_;
    std::map<std::type_index, std::any>               callbacks_;
};
}  // namespace sand::flows

#endif  // SAND_FLOWS_INBOUNDREQUESTDISPATCHER_HPP_
