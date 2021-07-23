#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>

#include <glog/logging.h>

#include "sanddnlnode.hpp"
#include "sanddnlnodelistener.hpp"
#include "sandversion.hpp"

namespace
{
constexpr char const *config_file_name = "dnl_node_config.json";

std::string get_app_data_dir()
{
#if defined(linux)
    return std::filesystem::path {std::getenv("HOME")} / ".sand";
#elif defined(_WIN32)
    return std::filesystem::path {std::getenv("APPDATA")} / "sand";
#else
#error "Unsupported OS"
#endif
}

bool write_file_if_not_exists(const std::string &path, const std::string &content)
{
    if (!std::filesystem::is_regular_file(path))
    {
        // If there is a file which is not regular and with the same name, delete it
        std::filesystem::remove_all(path);

        // Write default configuration to config.json
        std::ofstream fs {path};
        if (!fs)
        {
            std::cout << "Cannot open " << path << " for writing\n ";
            return false;
        }
        fs << content;
    }
    return true;
}

class NetworkActivityPrinter : public sand::SANDDNLNodeListener
{
public:
    void on_node_connected(const std::string &node_address) override
    {
        std::cout << node_address << " joined\n";
    }

    void on_node_disconnected(const std::string &node_address) override
    {
        std::cout << node_address << " left\n";
    }
};
}  // namespace

int main(int /*argc*/, char **argv)
{
    google::InitGoogleLogging(argv[0]);

    std::cout << "SAND Distributed Name List node app " << DNLAPP_VERSION << " (lib version "
              << sand::sand_version << ")\n";
    std::cout << "Author: " << PROGRAM_AUTHOR << '\n';
    std::cout << PROGRAM_LICENSE << "\n\n";

    std::string app_data_dir {get_app_data_dir()};

    if (!std::filesystem::is_directory(app_data_dir))
    {
        // If there is a regular file with the same name, delete it
        std::filesystem::remove(app_data_dir);

        std::error_code ec;
        std::filesystem::create_directories(app_data_dir, ec);
        if (ec)
        {
            std::cout << "Error while creating app data directory " << app_data_dir << ": "
                      << ec.message() << "\n";
            return EXIT_FAILURE;
        }
    }

    if (!write_file_if_not_exists(
            std::filesystem::path {app_data_dir} / config_file_name, SAND_CONFIGURATION))
    {
        return EXIT_FAILURE;
    }

    if (!write_file_if_not_exists(
            std::filesystem::path {app_data_dir} / DNL_NODE_LIST_FILE, DNL_NODE_LIST))
    {
        return EXIT_FAILURE;
    }

    sand::SANDDNLNode node {get_app_data_dir(), config_file_name};
    auto              network_activity_printer = std::make_shared<NetworkActivityPrinter>();
    node.register_listener(network_activity_printer);

    std::cout << "Starting node...\n";
    if (!node.start())
    {
        std::cout << "Failed to start node, check the log file for details.\n";
        return EXIT_FAILURE;
    }
    std::cout << '\n';

    for (;;)
    {
    }

    return EXIT_SUCCESS;
}
