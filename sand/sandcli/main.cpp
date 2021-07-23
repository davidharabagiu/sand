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

        // Write default configuration to config.json
        std::string   config_file_path {std::filesystem::path {app_data_dir} / config_file_name};
        std::ofstream fs {config_file_path};
        if (!fs)
        {
            std::cout << "Cannot open " << config_file_path << " for reading\n ";
            return EXIT_FAILURE;
        }
        fs << SAND_CONFIGURATION;
    }

    std::cout << SAND_CONFIGURATION << "\n";
    return 0;

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

        if (!exec_cmd->execute(node, error_message))
        {
            std::cout << error_message << '\n';
        }

        if (exec_cmd->should_terminate_program_after_execution())
        {
            break;
        }
    }

    return EXIT_SUCCESS;
}
