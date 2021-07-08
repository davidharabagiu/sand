#ifndef SAND_CONFIG_CONFIGKEYS_HPP_
#define SAND_CONFIG_CONFIGKEYS_HPP_

#include <string>
#include <type_traits>

namespace sand::config
{
class ConfigKey
{
public:
    enum EnumType
    {
        FIRST_KEY = 0,

        PORT = FIRST_KEY,
        KNOWN_DNL_NODES_LIST_PATH,
        IS_DNL_NODE,
        INITIAL_PEER_COUNT,
        SEARCH_PROPAGATION_DEGREE,
        SEARCH_TIMEOUT,
        ROUTING_TABLE_ENTRY_TIMEOUT,
        RECV_FILE_TIMEOUT,
        DROP_POINT_REQUEST_TIMEOUT,
        DROP_POINT_TRANSFER_TIMEOUT,
        LIFT_PROXY_REQUEST_TIMEOUT,
        LIFT_PROXY_TRANSFER_TIMEOUT,
        METADATA_FILE_PATH,
        FILE_STORAGE_PATH,
        MAX_PART_SIZE,
        MAX_CHUNK_SIZE,
        MAX_TEMP_STORAGE_SIZE,
        DNL_SYNC_PERIOD,

        KEY_COUNT
    };

    ConfigKey(const std::string &str_key);

    ConfigKey(EnumType k)
        : key_ {k}
    {}

    [[nodiscard]] std::string to_string() const
    {
        if (key_ >= 0 && key_ < KEY_COUNT)
        {
            return string_vals[key_];
        }
        return "";
    }

    [[nodiscard]] EnumType to_enum_type() const
    {
        return key_;
    }

    operator EnumType() const
    {
        return to_enum_type();
    }

    explicit operator std::string() const
    {
        return to_string();
    }

private:
    EnumType key_;

    static constexpr char const *string_vals[] {"port", "known_dnl_nodes_list_path", "is_dnl_node",
        "initial_peer_count", "search_propagation_degree", "search_timeout",
        "routing_table_entry_timeout", "recv_file_timeout", "drop_point_request_timeout",
        "drop_point_transfer_timeout", "lift_proxy_request_timeout", "lift_proxy_transfer_timeout",
        "metadata_file_path", "file_storage_path", "max_part_size", "max_chunk_size",
        "max_temp_storage_size", "dnl_sync_period"};
};
}  // namespace sand::config

#endif  // SAND_CONFIG_CONFIGKEYS_HPP_
