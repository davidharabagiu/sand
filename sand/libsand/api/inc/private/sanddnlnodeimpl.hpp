#ifndef SAND_API_SANDDNLNODEIMPL_HPP_
#define SAND_API_SANDDNLNODEIMPL_HPP_

#include <memory>
#include <mutex>
#include <string>

#include <boost/asio.hpp>

#include "address.hpp"
#include "config.hpp"
#include "dnlflowlistenerdelegate.hpp"
#include "listenergroup.hpp"
#include "sanddnlnodelistener.hpp"

namespace sand
{
namespace utils
{
class ThreadPool;
class IOThreadPool;
}  // namespace utils

namespace flows
{
// Forward declarations
class DNLFlow;
}  // namespace flows

class SANDDNLNodeImpl
{
public:
    SANDDNLNodeImpl(const std::string &app_data_dir_path, const std::string &config_file_name);
    ~SANDDNLNodeImpl();

    bool register_listener(const std::shared_ptr<SANDDNLNodeListener> &listener);
    bool unregister_listener(const std::shared_ptr<SANDDNLNodeListener> &listener);

    bool start();
    bool stop();

private:
    void on_node_connected(network::IPv4Address node_address);
    void on_node_disconnected(network::IPv4Address node_address);

    enum class State
    {
        IDLE,
        STARTING,
        RUNNING,
        STOPPING
    };

    State state() const;
    void  set_state(State new_state);

    constexpr static const char *to_string(State state)
    {
        switch (state)
        {
            case State::IDLE: return "IDLE";
            case State::STARTING: return "STARTING";
            case State::RUNNING: return "RUNNING";
            case State::STOPPING: return "STOPPING";
            default: return "INVALID";
        }
    }

    State                                     state_;
    config::Config                            cfg_;
    std::unique_ptr<flows::DNLFlow>           dnl_flow_;
    std::shared_ptr<utils::ThreadPool>        thread_pool_;
    std::shared_ptr<utils::IOThreadPool>      io_thread_pool_;
    std::unique_ptr<boost::asio::io_context>  tcp_server_io_ctx_;
    std::unique_ptr<boost::asio::io_context>  tcp_sender_io_ctx_;
    DNLFlowListenerDelegate                   dnl_flow_listener_;
    utils::ListenerGroup<SANDDNLNodeListener> listener_group_;
    mutable std::mutex                        mutex_;
};
}  // namespace sand

#endif  // SAND_API_SANDDNLNODEIMPL_HPP_
