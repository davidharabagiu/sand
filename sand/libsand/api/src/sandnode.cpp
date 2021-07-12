#include "sandnode.hpp"

#include "sandnodeimpl.hpp"

namespace sand
{
SANDNode::SANDNode(const std::string &app_data_dir_path, const std::string &config_file_name)
    : impl_ {std::make_unique<SANDNodeImpl>(app_data_dir_path, config_file_name)}
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

bool SANDNode::start()
{
    return impl_->start();
}

bool SANDNode::stop()
{
    return impl_->stop();
}

bool SANDNode::download_file(
    const std::string &file_hash, const std::string &file_name, std::string &error_string)
{
    return impl_->download_file(file_hash, file_name, error_string);
}
}  // namespace sand
