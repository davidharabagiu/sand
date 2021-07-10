#include "sandnode.hpp"

#include "sandnodeimpl.hpp"

namespace sand
{
SANDNode::SANDNode(const std::string &config_file_path)
    : impl_ {std::make_unique<SANDNodeImpl>(config_file_path)}
{}

SANDNode::SANDNode(SANDNode &&other) noexcept
    : impl_ {std::move(other.impl_)}
{}

SANDNode &SANDNode::operator=(SANDNode &&rhs) noexcept
{
    impl_ = std::move(rhs.impl_);
    return *this;
}

SANDNode::~SANDNode() = default;

bool SANDNode::register_listener(const std::shared_ptr<SANDNodeListener> &listener)
{
    return impl_->register_listener(listener);
}

bool SANDNode::unregister_listener(const std::shared_ptr<SANDNodeListener> &listener)
{
    return impl_->unregister_listener(listener);
}

bool SANDNode::initialize()
{
    return impl_->initialize();
}

bool SANDNode::uninitialize()
{
    return impl_->uninitialize();
}
}  // namespace sand
