#include "defaultconfigvalues.hpp"

#include <filesystem>
#include <string>

#include <glog/logging.h>

namespace
{
std::string path_join(const std::string &directory, const std::string &file_name)
{
    return (std::filesystem::path {directory} / file_name).string();
}
}  // namespace

namespace sand
{
DefaultConfigValues::DefaultConfigValues(const std::string &app_data_dir_path, bool is_dnl_node)
    : default_values_ {/* PORT */ 7874LL,
          /* KNOWN_DNL_NODES_LIST_PATH */ path_join(app_data_dir_path, "dnl_config.txt"),
          /* IS_DNL_NODE */ is_dnl_node, /* INITIAL_PEER_COUNT */ 10LL,
          /* SEARCH_PROPAGATION_DEGREE */ 3LL, /* SEARCH_TIMEOUT */ 60LL /* = 1 minute */,
          /* ROUTING_TABLE_ENTRY_TIMEOUT */ 60LL /* = 1 minute */,
          /* RECV_FILE_TIMEOUT */ 60LL /* = 1 minute */,
          /* DROP_POINT_REQUEST_TIMEOUT */ 60LL /* = 1 minute */,
          /* DROP_POINT_TRANSFER_TIMEOUT */ 60LL /* = 1 minute */,
          /* LIFT_PROXY_REQUEST_TIMEOUT */ 60LL /* = 1 minute */,
          /* LIFT_PROXY_TRANSFER_TIMEOUT */ 60LL /* = 1 minute */,
          /* CONFIRM_TRANSFER_TIMEOUT */ 60LL /* = 1 minute */,
          /* METADATA_FILE_PATH */ path_join(app_data_dir_path, "storage_metadata.json"),
          /* FILE_STORAGE_PATH */ path_join(app_data_dir_path, "storage"),
          /* MAX_PART_SIZE */ 128LL * 1024 * 1024 /* = 128 MiB */,
          /* MAX_CHUNK_SIZE */ 4LL * 1024 * 1024 /* = 4 MiB */,
          /* MAX_TEMP_STORAGE_SIZE */ 1LL * 1024 * 1024 * 1024 /* = 1 GiB */,
          /* DNL_SYNC_PERIOD */ 10LL * 60 /* = 10 minutes */}
{}

std::any DefaultConfigValues::get(const config::ConfigKey &key) const
{
    if (key < config::ConfigKey::FIRST_KEY || key >= config::ConfigKey::KEY_COUNT)
    {
        LOG(ERROR) << "Invalid key " << key;
        return {};
    }
    return default_values_[key];
}
}  // namespace sand
