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
        KNOWN_DNL_NODES_LIST_FILE,
        INITIAL_PEER_COUNT,
        SEARCH_PROPAGATION_DEGREE,
        SEARCH_TIMEOUT,
        SEARCH_MESSAGE_TTL,
        ROUTING_TABLE_ENTRY_TIMEOUT,
        RECV_FILE_TIMEOUT,
        DROP_POINT_REQUEST_TIMEOUT,
        DROP_POINT_TRANSFER_TIMEOUT,
        LIFT_PROXY_REQUEST_TIMEOUT,
        LIFT_PROXY_TRANSFER_TIMEOUT,
        CONFIRM_TRANSFER_TIMEOUT,
        METADATA_FILE,
        FILE_STORAGE_DIR,
        MAX_PART_SIZE,
        MAX_CHUNK_SIZE,
        MAX_TEMP_STORAGE_SIZE,
        DNL_SYNC_PERIOD,

        KEY_COUNT
    };

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

    static constexpr char const *string_vals[] {"port", "known_dnl_nodes_list_file",
        "initial_peer_count", "search_propagation_degree", "search_timeout", "search_message_ttl",
        "routing_table_entry_timeout", "recv_file_timeout", "drop_point_request_timeout",
        "drop_point_transfer_timeout", "lift_proxy_request_timeout", "lift_proxy_transfer_timeout",
        "confirm_transfer_timeout", "metadata_file", "file_storage_dir", "max_part_size",
        "max_chunk_size", "max_temp_storage_size", "dnl_sync_period"};
};
}  // namespace sand::config

#endif  // SAND_CONFIG_CONFIGKEYS_HPP_
