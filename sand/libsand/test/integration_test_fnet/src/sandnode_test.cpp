#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

#include "fakenet.hpp"
#include "iothreadpool.hpp"
#include "messages.hpp"
#include "sandnode.hpp"
#include "singleton.hpp"
#include "tcpmessagelistener.hpp"
#include "tcpsenderimpl.hpp"
#include "tcpserverimpl.hpp"

using namespace ::testing;
using namespace ::sand;
using namespace ::sand::network;
using namespace ::sand::protocol;
using namespace ::sand::utils;
using namespace std::literals::chrono_literals;

namespace fs = std::filesystem;

namespace
{
/*
 * Params:
 * 0 - Number of nodes
 * 1 - Transfer size
 */
class SandNodeTest : public TestWithParam<std::tuple<size_t, size_t>>
{
private:
    class TCPMessageListenerDelegate : public TCPMessageListener
    {
    public:
        explicit TCPMessageListenerDelegate(SandNodeTest &parent)
            : parent_ {parent}
        {}

        void on_message_received(IPv4Address from, const uint8_t *data, size_t len) override
        {
            parent_.handle_message_as_dnl_node(from, data, len);
        }

    private:
        SandNodeTest &parent_;
    };

protected:
    void SetUp() override
    {
        fake_net_ = &Singleton<FakeNet>::get();
        init_app_data_dirs();
        init_fake_dnl();
    }

    void TearDown() override
    {
        fs_cleanup();
        Singleton<FakeNet>::reset();
    }

    void init_app_data_dirs()
    {
        app_data_dirs_.reserve(number_of_nodes());
        for (size_t i = 0; i != number_of_nodes(); ++i)
        {
            std::ostringstream ss_dirname;
            ss_dirname << "app_data_" << i;
            fs::path dirpath {fs::current_path() / ss_dirname.str()};
            fs::path config_path {dirpath / config_file_name_};
            fs::path dnl_list_path {dirpath / dnl_list_file_name_};
            app_data_dirs_.push_back(dirpath);

            fs::create_directories(dirpath);
            std::ofstream config_fs {config_path};
            config_fs << config_text_;
            std::ofstream dnl_list_fs {dnl_list_path};
            dnl_list_fs << dnl_address_str_ << '\n';
        }
    }

    void fs_cleanup()
    {
        for (const std::string &dir : app_data_dirs_)
        {
            fs::remove_all(dir);
        }
    }

    void init_fake_dnl()
    {
        dnl_address_ = conversion::to_ipv4_address(dnl_address_str_);
        fake_net_->next_node(dnl_address_);
        dnl_node_server_           = std::make_unique<TCPServerImpl>();
        dnl_node_sender_           = std::make_unique<TCPSenderImpl>();
        dnl_node_message_listener_ = std::make_shared<TCPMessageListenerDelegate>(*this);
        dnl_node_server_->register_listener(dnl_node_message_listener_);
    }

    void handle_message_as_dnl_node(IPv4Address from, const uint8_t *data, size_t len)
    {
        /*
         * Offload to another thread to allow further processing in the node before a reply will be
         * received.
         */
        thread_pool_.add_job([this, from, request = std::vector<uint8_t>(data, data + len)](
                                 const CompletionToken &) {
            std::cout << "Got request of size " << request.size() << " from "
                      << conversion::to_string(from) << '\n';

            std::this_thread::sleep_for(10ms);

            if (request[0] == uint8_t(MessageCode::PUSH))
            {
                // Add to node address list
                node_addresses_.push_back(from);

                // Construct reply
                std::vector<uint8_t> reply(11);
                reply[0] = uint8_t(MessageCode::REPLY);
                std::copy_n(request.data() + 1, 8, reply.data() + 1);  // Request ID
                reply[9]  = uint8_t(StatusCode::OK);
                reply[10] = uint8_t(MessageCode::PUSH);

                // Send reply
                ASSERT_TRUE(dnl_node_sender_->send(from, 0, reply.data(), reply.size()).get());
            }
            else if (request[0] == uint8_t(MessageCode::PULL))
            {}
        });
    }

    static size_t number_of_nodes()
    {
        return std::get<0>(GetParam());
    }

    static size_t transfer_size()
    {
        return std::get<1>(GetParam());
    }

    FakeNet *                                   fake_net_;
    std::vector<std::string>                    app_data_dirs_;
    std::unique_ptr<TCPServerImpl>              dnl_node_server_;
    std::unique_ptr<TCPSenderImpl>              dnl_node_sender_;
    std::shared_ptr<TCPMessageListenerDelegate> dnl_node_message_listener_;
    IPv4Address                                 dnl_address_;
    std::vector<std::unique_ptr<SANDNode>>      nodes_;
    std::vector<IPv4Address>                    node_addresses_;
    IOThreadPool                                thread_pool_;

    static constexpr char const *config_file_name_ = "config.json";

private:
    static constexpr char const *dnl_list_file_name_ = "dnl_node_list.txt";
    static constexpr char const *dnl_address_str_    = "1.0.0.1";
    static constexpr char const *config_text_ =
        "{\n"
        "  \"network\": {\n"
        "    \"port\": 12289\n"
        "  },\n"
        "  \"dnl\": {\n"
        "    \"known_dnl_nodes_list_file\": \"dnl_node_list.txt\"\n"
        "  },\n"
        "  \"peer_discovery\": {\n"
        "    \"initial_peer_count\": 10\n"
        "  },\n"
        "  \"search\": {\n"
        "    \"search_propagation_degree\": 3,\n"
        "    \"search_timeout\": 60,\n"
        "    \"search_message_ttl\": 10,\n"
        "    \"routing_table_entry_timeout\": 60\n"
        "  },\n"
        "  \"transfer\": {\n"
        "    \"recv_file_timeout\": 60,\n"
        "    \"drop_point_request_timeout\": 60,\n"
        "    \"drop_point_transfer_timeout\": 60,\n"
        "    \"lift_proxy_request_timeout\": 60,\n"
        "    \"lift_proxy_transfer_timeout\": 60,\n"
        "    \"confirm_transfer_timeout\": 60,\n"
        "    \"max_part_size\": 134217728,\n"
        "    \"max_chunk_size\": 4194304\n"
        "  },\n"
        "  \"storage\": {\n"
        "    \"metadata_file\": \"storage_metadata.json\",\n"
        "    \"file_storage_dir\": \"storage\",\n"
        "    \"max_temp_storage_size\": 1073741824\n"
        "  }\n"
        "}\n";
};
}  // namespace

TEST_P(SandNodeTest, Init_Transfer_Uninit)
{
    // Init nodes
    for (size_t i = 0; i != number_of_nodes(); ++i)
    {
        auto node = std::make_unique<SANDNode>(app_data_dirs_[i], config_file_name_);
        fake_net_->next_node();
        ASSERT_TRUE(node->start());
        nodes_.push_back(std::move(node));
    }

    // Stop nodes
    for (const auto &node : nodes_)
    {
        ASSERT_TRUE(node->stop());
    }
    nodes_.clear();
}

INSTANTIATE_TEST_SUITE_P(SandNodeTests, SandNodeTest, Values(std::make_tuple(20, 512)));
