#ifndef SAND_API_SANDNODEIMPL_HPP_
#define SAND_API_SANDNODEIMPL_HPP_

#include <memory>
#include <string>

#include "listenergroup.hpp"
#include "sandnodelistener.hpp"

namespace sand
{
class SANDNodeImpl
{
public:
    explicit SANDNodeImpl(const std::string &config_file_path);

    bool register_listener(const std::shared_ptr<SANDNodeListener> &listener);
    bool unregister_listener(const std::shared_ptr<SANDNodeListener> &listener);

    bool initialize();
    bool uninitialize();

private:
    utils::ListenerGroup<SANDNodeListener> listener_group_;
};
}  // namespace sand

#endif  // SAND_API_SANDNODEIMPL_HPP_
