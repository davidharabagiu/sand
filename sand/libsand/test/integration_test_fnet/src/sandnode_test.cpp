#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

#include "base64encoderimpl.hpp"
#include "fakenet.hpp"
#include "filehashinterpreterimpl.hpp"
#include "mainexecuter.hpp"
#include "messages.hpp"
#include "random.hpp"
#include "sandnode.hpp"
#include "sandnodelistener.hpp"
#include "sha3hasherimpl.hpp"
#include "singleton.hpp"
#include "tcpmessagelistener.hpp"
#include "tcpsenderimpl.hpp"
#include "tcpserverimpl.hpp"

using namespace ::testing;
using namespace ::sand;
using namespace ::sand::network;
using namespace ::sand::protocol;
using namespace ::sand::utils;
using namespace ::sand::storage;
using namespace ::sand::crypto;
using namespace ::std::chrono_literals;
namespace fs = ::std::filesystem;

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
        if (Test::HasFailure())
        {
            std::this_thread::sleep_for(3s);
        }

        dnl_node_sender_.reset();
        dnl_node_server_.reset();
        fs_cleanup();
        Singleton<FakeNet>::reset();
    }

    void write_file(const std::string &path)
    {
        std::ofstream fs {path, std::ios::binary};
        uint64_t      bytes;
        for (size_t i = 0; i != transfer_size(); i += sizeof(bytes))
        {
            bytes = rng_.next<uint64_t>();
            fs.write(reinterpret_cast<char *>(&bytes),
                std::streamsize(std::min(sizeof(bytes), transfer_size() - i)));
        }
    }

    std::string random_file_name()
    {
        std::ostringstream ss;
        auto               len = rng_.next<size_t>(5, 10);
        for (size_t i = 0; i != len; ++i)
        {
            ss << rng_.next<char>('a', 'z');
        }
        return ss.str();
    }

    static std::string compute_file_hash(const std::string &path)
    {
        FileHashInterpreterImpl fhi {
            std::make_unique<Base64EncoderImpl>(), std::make_unique<SHA3HasherImpl>()};
        MainExecuter executer;
        AHash        bin_hash;
        fhi.create_hash(path, bin_hash, executer).wait();
        return fhi.encode(bin_hash);
    }

    static bool compare_files(const std::string &file1, const std::string &file2)
    {
        std::ifstream fs1 {file1, std::ios::binary | std::ios::ate};
        std::ifstream fs2 {file2, std::ios::binary | std::ios::ate};
        if (!fs1 || !fs2)
        {
            return false;
        }

        if (fs1.tellg() != fs2.tellg())
        {
            return false;
        }
        fs1.seekg(0, std::ios::beg);
        fs2.seekg(0, std::ios::beg);

        constexpr size_t buffer_size = 4096;
        char             buffer1[buffer_size];
        char             buffer2[buffer_size];
        for (;;)
        {
            fs1.read(buffer1, buffer_size);
            fs2.read(buffer2, buffer_size);
            if (!std::equal(buffer1, buffer1 + fs1.gcount(), buffer2))
            {
                return false;
            }
            if (!fs1 || !fs2)
            {
                break;
            }
        }

        return true;
    }

    static size_t number_of_nodes()
    {
        return std::get<0>(GetParam());
    }

    static size_t transfer_size()
    {
        return std::get<1>(GetParam());
    }

    FakeNet *                fake_net_;
    std::vector<std::string> app_data_dirs_;
    size_t                   bye_msg_count_ = 0;

    static constexpr char const *config_file_name_ = "config.json";
    static constexpr char const *storage_dir_name_ = "storage";

private:
    void init_app_data_dirs()
    {
        size_t node_cnt = number_of_nodes();

        app_data_dirs_.reserve(node_cnt);
        for (size_t i = 0; i != node_cnt; ++i)
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

    void handle_message_as_dnl_node(IPv4Address from, const uint8_t *data, size_t /*len*/)
    {
        if (data[0] == uint8_t(MessageCode::PUSH))
        {
            // Add to node address list
            {
                std::lock_guard lock {mutex_};
                node_addresses_.push_back(from);
            }

            // Construct reply
            std::vector<uint8_t> reply(11);
            reply[0] = uint8_t(MessageCode::REPLY);
            std::copy_n(data + 1, 8, reply.data() + 1);  // Request ID
            reply[9]  = uint8_t(StatusCode::OK);
            reply[10] = uint8_t(MessageCode::PUSH);

            // Send reply
            ASSERT_TRUE(dnl_node_sender_->send(from, 0, reply.data(), reply.size()).get());
        }
        else if (data[0] == uint8_t(MessageCode::PULL))
        {
            size_t                   addr_count = data[9];
            std::vector<IPv4Address> addrs;

            // Pick some nodes
            {
                std::lock_guard lock {mutex_};
                addrs = pick_addresses(addr_count, from);
            }

            // Construct reply
            std::vector<uint8_t> reply(12 + 4 * addrs.size());
            reply[0] = uint8_t(MessageCode::REPLY);
            std::copy_n(data + 1, 8, reply.data() + 1);  // Request ID
            reply[9]  = uint8_t(StatusCode::OK);
            reply[10] = uint8_t(MessageCode::PULL);
            reply[11] = uint8_t(addrs.size());
            for (size_t i = 0; i != addrs.size(); ++i)
            {
                std::copy_n(
                    reinterpret_cast<const uint8_t *>(&addrs[i]), 4, reply.data() + 12 + i * 4);
            }

            // Send reply
            ASSERT_TRUE(dnl_node_sender_->send(from, 0, reply.data(), reply.size()).get());
        }
        else if (data[0] == uint8_t(MessageCode::BYE))
        {
            std::lock_guard lock {mutex_};
            ++bye_msg_count_;
        }
        else
        {
            FAIL();
        }
    }

    std::vector<IPv4Address> pick_addresses(size_t cnt, IPv4Address exclude)
    {
        std::set<IPv4Address> result;
        cnt = std::min(cnt, node_addresses_.size() - 1);
        for (size_t i = 0; i != cnt; ++i)
        {
            IPv4Address a;
            do
            {
                a = node_addresses_[rng_.next(node_addresses_.size() - 1)];
            } while (result.count(a) != 0 || a == exclude);
            result.insert(a);
        }
        return std::vector<IPv4Address>(result.cbegin(), result.cend());
    }

    std::unique_ptr<TCPServerImpl>              dnl_node_server_;
    std::unique_ptr<TCPSenderImpl>              dnl_node_sender_;
    std::shared_ptr<TCPMessageListenerDelegate> dnl_node_message_listener_;
    IPv4Address                                 dnl_address_;
    std::vector<IPv4Address>                    node_addresses_;
    Random                                      rng_;
    std::mutex                                  mutex_;

    static constexpr char const *dnl_list_file_name_ = "dnl_node_list.txt";
    static constexpr char const *dnl_address_str_    = "1.0.0.1";
    static constexpr char const *config_text_ =
        "{\n"
        "  \"network\": {\n"
        "    \"port\": 12289,\n"
        "    \"request_timeout\": 5\n"
        "  },\n"
        "  \"dnl\": {\n"
        "    \"known_dnl_nodes_list_file\": \"dnl_node_list.txt\"\n"
        "  },\n"
        "  \"peer_discovery\": {\n"
        "    \"initial_peer_count\": 10\n"
        "  },\n"
        "  \"search\": {\n"
        "    \"search_propagation_degree\": 3,\n"
        "    \"search_timeout\": 10,\n"
        "    \"search_message_ttl\": 10,\n"
        "    \"routing_table_entry_timeout\": 10\n"
        "  },\n"
        "  \"transfer\": {\n"
        "    \"recv_file_timeout\": 0,\n"
        "    \"drop_point_request_timeout\": 10,\n"
        "    \"drop_point_transfer_timeout\": 10,\n"
        "    \"lift_proxy_request_timeout\": 10,\n"
        "    \"lift_proxy_transfer_timeout\": 10,\n"
        "    \"confirm_transfer_timeout\": 10,\n"
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

class NodeListener : public SANDNodeListener
{
public:
    void on_file_found() override
    {
        std::cout << "Transfer progress: File found\n";
    }

    void on_transfer_progress_changed(size_t bytes_transferred, size_t total_bytes) override
    {
        std::cout << "Transfer progress: " << bytes_transferred << " / " << total_bytes << "\n";
    }
};
}  // namespace

TEST_P(SandNodeTest, Start_Transfer_Stop)
{
    // Create source file
    std::cout << "Generating file...\n";
    auto src_node_storage_path =
        fs::path {app_data_dirs_[number_of_nodes() - 1]} / storage_dir_name_;
    fs::create_directory(src_node_storage_path);
    auto src_file_path = src_node_storage_path / random_file_name();
    write_file(src_file_path);
    std::string file_hash {compute_file_hash(src_file_path)};

    // Determine dest file path
    std::string dst_file_name = random_file_name();
    auto        dst_file_path = fs::path {app_data_dirs_[0]} / storage_dir_name_ / dst_file_name;

    std::vector<std::unique_ptr<SANDNode>> nodes;

    // Init nodes
    std::cout << "Starting nodes...\n";
    for (size_t i = 0; i != number_of_nodes(); ++i)
    {
        auto node = std::make_unique<SANDNode>(app_data_dirs_[i], config_file_name_);
        fake_net_->next_node();
        ASSERT_TRUE(node->start());
        nodes.push_back(std::move(node));
    }

    // Wait for all nodes to fill their peer list
    std::this_thread::sleep_for(1s);

    // Make a transfer
    std::cout << "Starting transfer...\n";
    std::string err_string;
    auto        listener = std::make_shared<NodeListener>();
    ASSERT_TRUE(nodes[0]->register_listener(listener));
    EXPECT_TRUE(nodes[0]->download_file(file_hash, dst_file_name, err_string));
    ASSERT_EQ(err_string, "");

    // Stop nodes
    std::cout << "Stopping nodes...\n";
    for (auto &node : nodes)
    {
        ASSERT_TRUE(node->stop());
    }
    nodes.clear();

    // Wait for all BYE messages to arrive
    std::this_thread::sleep_for(1s);

    // Verify that files are equal
    ASSERT_TRUE(fs::is_regular_file(dst_file_path));
    ASSERT_EQ(fs::file_size(dst_file_path), transfer_size());
    ASSERT_TRUE(compare_files(src_file_path, dst_file_path));

    ASSERT_EQ(number_of_nodes(), bye_msg_count_);
}

INSTANTIATE_TEST_SUITE_P(
    SandNodeTests, SandNodeTest, Values(std::make_tuple(20, 200000000)));
