#ifndef SAND_API_SANDDNLNODELISTENER_HPP_
#define SAND_API_SANDDNLNODELISTENER_HPP_

namespace sand
{
class SANDDNLNodeListener
{
public:
    virtual ~SANDDNLNodeListener() = default;

    virtual void on_node_connected(const std::string &node_address)     = 0;
    virtual void on_node_disconnected(const std::string &&node_address) = 0;
};
}  // namespace sand

#endif  // SAND_API_SANDDNLNODELISTENER_HPP_
