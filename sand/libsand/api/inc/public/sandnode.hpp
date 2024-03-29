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
    SANDNode(const std::string &app_data_dir_path, const std::string &config_file_name);
    SANDNode(SANDNode &&other) noexcept;
    SANDNode &operator=(SANDNode &&rhs) noexcept;
    ~SANDNode();

    bool register_listener(const std::shared_ptr<SANDNodeListener> &listener);
    bool unregister_listener(const std::shared_ptr<SANDNodeListener> &listener);

    bool start();
    bool stop();

    bool download_file(
        const std::string &file_hash, const std::string &file_name, std::string &error_string);

private:
    std::unique_ptr<SANDNodeImpl> impl_;
};
}  // namespace sand

#endif  // SAND_API_SANDNODE_HPP_
