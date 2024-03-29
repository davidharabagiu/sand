#include "defaultconfigvalues.hpp"

#include <string>

#include <glog/logging.h>

namespace sand
{
DefaultConfigValues::DefaultConfigValues()
    : default_values_ {/* PORT */ 12289LL,
          /* KNOWN_DNL_NODES_LIST_FILE */ std::string {"dnl_node_list.txt"},
          /* INITIAL_PEER_COUNT */ 10LL,
          /* SEARCH_PROPAGATION_DEGREE */ 3LL, /* SEARCH_TIMEOUT */ 60LL /* = 1 minute */,
          /* SEARCH_MESSAGE_TTL */ 10LL, /* ROUTING_TABLE_ENTRY_TIMEOUT */ 60LL /* = 1 minute */,
          /* RECV_FILE_TIMEOUT */ 60LL /* = 1 minute */,
          /* DROP_POINT_REQUEST_TIMEOUT */ 60LL /* = 1 minute */,
          /* DROP_POINT_TRANSFER_TIMEOUT */ 60LL /* = 1 minute */,
          /* LIFT_PROXY_REQUEST_TIMEOUT */ 60LL /* = 1 minute */,
          /* LIFT_PROXY_TRANSFER_TIMEOUT */ 60LL /* = 1 minute */,
          /* CONFIRM_TRANSFER_TIMEOUT */ 60LL /* = 1 minute */,
          /* METADATA_FILE */ std::string {"storage_metadata.json"},
          /* FILE_STORAGE_DIR */ std::string {"storage"},
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
