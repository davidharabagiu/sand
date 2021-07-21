#ifndef SANDCLI_COMMANDINTERPRETER_HPP_
#define SANDCLI_COMMANDINTERPRETER_HPP_

#include <memory>
#include <string>

#include "command.hpp"
#include "executablecommand.hpp"

namespace sandcli
{
class CommandInterpreter
{
public:
    std::unique_ptr<ExecutableCommand> interpret(const Command &command, std::string &err) const;
};
}  // namespace sandcli

#endif  // SANDCLI_COMMANDINTERPRETER_HPP_
