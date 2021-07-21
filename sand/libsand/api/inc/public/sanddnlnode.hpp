#ifndef SAND_API_SANDDNLNODE_HPP_
#define SAND_API_SANDDNLNODE_HPP_

#include <memory>
#include <string>

#include "sandapidefs.h"

namespace sand
{
// Forward declarations
class SANDDNLNodeImpl;
class SANDDNLNodeListener;

class SAND_API SANDDNLNode
{
public:
    SANDDNLNode(const std::string &app_data_dir_path, const std::string &config_file_name);
    SANDDNLNode(SANDDNLNode &&other) noexcept;
    SANDDNLNode &operator=(SANDDNLNode &&rhs) noexcept;
    ~SANDDNLNode();

    bool register_listener(const std::shared_ptr<SANDDNLNodeListener> &listener);
    bool unregister_listener(const std::shared_ptr<SANDDNLNodeListener> &listener);

    bool start();
    bool stop();

private:
    std::unique_ptr<SANDDNLNodeImpl> impl_;
};
}  // namespace sand

#endif  // SAND_API_SANDDNLNODE_HPP_
