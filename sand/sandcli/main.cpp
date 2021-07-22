#include <iostream>
#include <memory>

#include <glog/logging.h>

#include "commandinterpreter.hpp"
#include "commandreader.hpp"
#include "sandnode.hpp"
#include "sandnodelistener.hpp"

namespace
{
constexpr char const *config_file_name = "config.json";

class TransferProgressListener : public sand::SANDNodeListener
{
public:
    void on_transfer_progress_changed(size_t bytes_transferred, size_t total_bytes) override
    {
        (void) bytes_transferred;
        (void) total_bytes;
    }
};
}  // namespace

int main(int /*argc*/, char **argv)
{
    google::InitGoogleLogging(argv[0]);

    sand::SANDNode node {APP_DATA_DIR, config_file_name};
    auto           node_listener = std::make_shared<TransferProgressListener>();
    node.register_listener(node_listener);

    if (!node.start())
    {
        std::cout << "Failed to start node, check the log file for details.\n";
        return 0;
    }

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

    return 0;
}
