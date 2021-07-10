#ifndef SAND_API_SANDNODE_HPP_
#define SAND_API_SANDNODE_HPP_

#include <memory>
#include <string>

#include "sandapidefs.h"

namespace sand
{
// Forward declarations
class SANDNodeImpl;
class SANDNodeListener;

class SAND_API SANDNode
{
public:
    explicit SANDNode(const std::string &config_file_path);
    SANDNode(SANDNode &&other) noexcept;
    SANDNode &operator=(SANDNode &&rhs) noexcept;
    ~SANDNode();

    bool register_listener(const std::shared_ptr<SANDNodeListener> &listener);
    bool unregister_listener(const std::shared_ptr<SANDNodeListener> &listener);

    bool initialize();
    bool uninitialize();

private:
    std::unique_ptr<SANDNodeImpl> impl_;
};
}  // namespace sand

#endif  // SAND_API_SANDNODE_HPP_
