#include "sandnodeimpl.hpp"

#include <glog/logging.h>

namespace sand
{
SANDNodeImpl::SANDNodeImpl(const std::string & /*config_file_path*/)
{}

bool SANDNodeImpl::register_listener(const std::shared_ptr<SANDNodeListener> &listener)
{
    return listener_group_.add(listener);
}

bool SANDNodeImpl::unregister_listener(const std::shared_ptr<SANDNodeListener> &listener)
{
    return listener_group_.remove(listener);
}

bool SANDNodeImpl::initialize()
{
    LOG(ERROR) << "Not implemented";
    return false;
}

bool SANDNodeImpl::uninitialize()
{
    LOG(ERROR) << "Not implemented";
    return false;
}
}  // namespace sand
