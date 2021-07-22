#include "commandinterpreter.hpp"

#include "exitcommand.hpp"
#include "getfilecommand.hpp"

namespace sandcli
{
namespace
{
constexpr char const *get_file_command_name = "get";
constexpr char const *exit_command_name     = "exit";
}  // namespace

std::unique_ptr<ExecutableCommand> CommandInterpreter::interpret(
    const Command &command, std::string &err) const
{
    if (!command)
    {
        err = "Invalid command object";
        return nullptr;
    }

    if (command.cmd == get_file_command_name)
    {
        if (command.args.size() != 2)
        {
            err = "Usage: get {file_hash} {file_name}";
            return nullptr;
        }
        return std::make_unique<GetFileCommand>(command.args[0], command.args[1]);
    }
    else if (command.cmd == exit_command_name)
    {
        if (!command.args.empty())
        {
            err = "Usage: exit";
            return nullptr;
        }
        return std::make_unique<ExitCommand>();
    }
    else
    {
        err = "Unknown command";
        return nullptr;
    }
}

std::unique_ptr<ExecutableCommand> CommandInterpreter::make_exit_command() const
{
    return std::make_unique<ExitCommand>();
}
}  // namespace sandcli
