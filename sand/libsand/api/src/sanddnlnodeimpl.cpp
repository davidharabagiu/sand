#include "sanddnlnodeimpl.hpp"

#include <filesystem>
#include <utility>

#include "defaultconfigvalues.hpp"
#include "dnlconfig.hpp"
#include "dnlflowimpl.hpp"
#include "inboundrequestdispatcher.hpp"
#include "iothreadpool.hpp"
#include "jsonconfigloader.hpp"
#include "messageserializerimpl.hpp"
#include "protocolmessagehandlerimpl.hpp"
#include "tcpsenderimpl.hpp"
#include "tcpserverimpl.hpp"
#include "textfilednlconfigloader.hpp"
#include "threadpool.hpp"

namespace sand
{
namespace
{
std::string path_join(const std::string &directory, const std::string &file_name)
{
    return (std::filesystem::path {directory} / file_name).string();
}
}  // namespace

SANDDNLNodeImpl::SANDDNLNodeImpl(
    const std::string &app_data_dir_path, const std::string &config_file_name)
    : state_ {State::IDLE}
    , cfg_ {config::JSONConfigLoader {path_join(app_data_dir_path, config_file_name)},
          std::make_unique<DefaultConfigValues>(app_data_dir_path, false)}
{
    dnl_flow_listener_.set_on_node_connected_cb(
        [this](auto &&a1) { on_node_connected(std::forward<decltype(a1)>(a1)); });
    dnl_flow_listener_.set_on_node_disconnected_cb(
        [this](auto &&a1) { on_node_disconnected(std::forward<decltype(a1)>(a1)); });
}

SANDDNLNodeImpl::~SANDDNLNodeImpl()
{
    if (state() == State::RUNNING)
    {
        stop();
    }
}

bool SANDDNLNodeImpl::register_listener(const std::shared_ptr<SANDDNLNodeListener> &listener)
{
    return listener_group_.add(listener);
}

bool SANDDNLNodeImpl::unregister_listener(const std::shared_ptr<SANDDNLNodeListener> &listener)
{
    return listener_group_.remove(listener);
}

bool SANDDNLNodeImpl::start()
{
    auto current_state = state();
    if (current_state != State::IDLE)
    {
        LOG(WARNING) << "Cannot start node from state " << to_string(current_state);
        return false;
    }

    set_state(State::STARTING);

    thread_pool_       = std::make_shared<utils::ThreadPool>();
    io_thread_pool_    = std::make_shared<utils::IOThreadPool>();
    tcp_sender_io_ctx_ = std::make_unique<boost::asio::io_context>();
    tcp_server_io_ctx_ = std::make_unique<boost::asio::io_context>();

    io_thread_pool_->add_job([this](const utils::CompletionToken &) { tcp_sender_io_ctx_->run(); });
    io_thread_pool_->add_job([this](const utils::CompletionToken &) { tcp_server_io_ctx_->run(); });

    auto tcp_sender               = std::make_shared<network::TCPSenderImpl>(*tcp_sender_io_ctx_);
    auto tcp_server               = std::make_shared<network::TCPServerImpl>(*tcp_server_io_ctx_,
        static_cast<unsigned short>(cfg_.get_integer(config::ConfigKey::PORT)));
    auto message_serializer       = std::make_shared<protocol::MessageSerializerImpl>();
    auto protocol_message_handler = std::make_shared<protocol::ProtocolMessageHandlerImpl>(
        tcp_sender, tcp_server, message_serializer, io_thread_pool_, cfg_);
    auto inbound_request_dispatcher =
        std::make_shared<flows::InboundRequestDispatcher>(protocol_message_handler);
    auto dnl_config =
        std::make_shared<config::DNLConfig>(std::make_unique<config::TextFileDNLConfigLoader>(
            cfg_.get_string(config::ConfigKey::KNOWN_DNL_NODES_LIST_PATH)));

    dnl_flow_ = std::make_unique<flows::DNLFlowImpl>(protocol_message_handler,
        inbound_request_dispatcher, dnl_config, thread_pool_, io_thread_pool_, cfg_);

    protocol_message_handler->initialize();
    inbound_request_dispatcher->initialize();
    dnl_flow_listener_.register_as_listener(*dnl_flow_);

    dnl_flow_->start();

    set_state(State::RUNNING);

    return true;
}

bool SANDDNLNodeImpl::stop()
{
    auto current_state = state();
    if (current_state != State::RUNNING)
    {
        LOG(WARNING) << "Cannot stop node from state " << to_string(current_state);
        return false;
    }

    set_state(State::STOPPING);

    tcp_server_io_ctx_->stop();
    tcp_sender_io_ctx_->stop();

    dnl_flow_->stop();
    dnl_flow_listener_.unregister_as_listener(*dnl_flow_);
    dnl_flow_.reset();

    thread_pool_.reset();
    io_thread_pool_.reset();
    tcp_server_io_ctx_.reset();
    tcp_sender_io_ctx_.reset();

    set_state(State::IDLE);

    return true;
}

void SANDDNLNodeImpl::on_node_connected(network::IPv4Address node_address)
{
    listener_group_.notify(
        &SANDDNLNodeListener::on_node_connected, network::conversion::to_string(node_address));
}

void SANDDNLNodeImpl::on_node_disconnected(network::IPv4Address node_address)
{
    listener_group_.notify(
        &SANDDNLNodeListener::on_node_disconnected, network::conversion::to_string(node_address));
}

SANDDNLNodeImpl::State SANDDNLNodeImpl::state() const
{
    std::lock_guard lock {mutex_};
    return state_;
}

void SANDDNLNodeImpl::set_state(SANDDNLNodeImpl::State new_state)
{
    std::lock_guard lock {mutex_};
    state_ = new_state;
}
}  // namespace sand
