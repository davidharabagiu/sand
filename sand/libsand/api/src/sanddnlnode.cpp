#include "sanddnlnode.hpp"

#include "sanddnlnodeimpl.hpp"
#include "sanddnlnodelistener.hpp"

namespace sand
{
SANDDNLNode::SANDDNLNode(const std::string &app_data_dir_path, const std::string &config_file_name)
    : impl_ {std::make_unique<SANDDNLNodeImpl>(app_data_dir_path, config_file_name)}
{}

SANDDNLNode::SANDDNLNode(SANDDNLNode &&other) noexcept
    : impl_ {std::move(other.impl_)}
{}

SANDDNLNode &SANDDNLNode::operator=(SANDDNLNode &&rhs) noexcept
{
    impl_ = std::move(rhs.impl_);
    return *this;
}

SANDDNLNode::~SANDDNLNode() = default;

bool SANDDNLNode::start()
{
    return impl_->start();
}

bool SANDDNLNode::stop()
{
    return impl_->stop();
}

bool SANDDNLNode::register_listener(const std::shared_ptr<SANDDNLNodeListener> &listener)
{
    return impl_->register_listener(listener);
}

bool SANDDNLNode::unregister_listener(const std::shared_ptr<SANDDNLNodeListener> &listener)
{
    return impl_->unregister_listener(listener);
}
}  // namespace sand
