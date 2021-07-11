#include "defaultconfigvalues.hpp"

#include <filesystem>
#include <string>

#include <glog/logging.h>

namespace
{
std::string get_full_path(const std::string &file_name)
{
    return (std::filesystem::path {APP_DATA_DIR} / file_name).string();
}
}  // namespace

namespace sand
{
DefaultConfigValues::DefaultConfigValues(bool is_dnl_node)
    : default_values_ {/* PORT */ 7874LL,
          /* KNOWN_DNL_NODES_LIST_PATH */ get_full_path("dnl_config.txt"),
          /* IS_DNL_NODE */ is_dnl_node, /* INITIAL_PEER_COUNT */ 10LL,
          /* SEARCH_PROPAGATION_DEGREE */ 3LL, /* SEARCH_TIMEOUT */ 0LL,
          /* ROUTING_TABLE_ENTRY_TIMEOUT */ 0LL, /* RECV_FILE_TIMEOUT */ 0LL,
          /* DROP_POINT_REQUEST_TIMEOUT */ 0LL, /* DROP_POINT_TRANSFER_TIMEOUT */ 0LL,
          /* LIFT_PROXY_REQUEST_TIMEOUT */ 0LL, /* LIFT_PROXY_TRANSFER_TIMEOUT */ 0LL,
          /* METADATA_FILE_PATH */ get_full_path("storage_metadata.json"),
          /* FILE_STORAGE_PATH */ get_full_path("storage"),
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
