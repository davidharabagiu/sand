#ifndef SAND_NETWORK_TCPSERVER_HPP_
#define SAND_NETWORK_TCPSERVER_HPP_

namespace sand::network
{
class TCPMessageListener;

class TCPServer
{
public:
    virtual ~TCPServer() = default;

    virtual bool register_listener(std::shared_ptr<TCPMessageListener> listener)   = 0;
    virtual bool unregister_listener(std::shared_ptr<TCPMessageListener> listener) = 0;
};
}  // namespace sand::network

#endif  // SAND_NETWORK_TCPSERVER_HPP_
