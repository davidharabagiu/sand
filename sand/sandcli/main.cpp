#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>

#include <glog/logging.h>

#include "commandinterpreter.hpp"
#include "commandreader.hpp"
#include "sandnode.hpp"
#include "sandversion.hpp"
#include "transferprogressprinter.hpp"

namespace
{
constexpr char const *config_file_name                   = "config.json";
constexpr int         transfer_progress_print_timeout_ms = 1000;

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
}  // namespace

int main(int /*argc*/, char **argv)
{
    google::InitGoogleLogging(argv[0]);

    std::cout << "SAND command line utility " << SANDCLI_VERSION << " (lib version "
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

    sand::SANDNode node {get_app_data_dir(), config_file_name};
    auto           progress_printer = std::make_shared<sandcli::TransferProgressPrinter>(
        std::cout, transfer_progress_print_timeout_ms);
    node.register_listener(progress_printer);

    std::cout << "Starting node...\n";
    if (!node.start())
    {
        std::cout << "Failed to start node, check the log file for details.\n";
        return EXIT_FAILURE;
    }
    std::cout << '\n';

    sandcli::CommandReader      cmd_reader {std::cin};
    sandcli::CommandInterpreter cmd_interpreter;

    int exit_status = EXIT_SUCCESS;

    for (;;)
    {
        std::cout << "> ";
        sandcli::Command cmd = cmd_reader.read_next_command();

        std::string                                 error_message;
        std::unique_ptr<sandcli::ExecutableCommand> exec_cmd =
            cmd ? cmd_interpreter.interpret(cmd, error_message) :
                  cmd_interpreter.make_exit_command();
        if (!exec_cmd)
        {
            std::cout << "Invalid command: " << error_message << '\n';
            continue;
        }

        bool exec_success;
        if (!(exec_success = exec_cmd->execute(node, error_message)))
        {
            std::cout << error_message << '\n';
        }

        if (exec_cmd->should_terminate_program_after_execution())
        {
            if (!exec_success)
            {
                exit_status = EXIT_FAILURE;
            }
            break;
        }
    }

    return exit_status;
}
