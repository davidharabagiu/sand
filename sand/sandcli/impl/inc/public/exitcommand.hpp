#ifndef SANDCLI_EXITCOMMAND_HPP_
#define SANDCLI_EXITCOMMAND_HPP_

#include <string>

#include "executablecommand.hpp"

namespace sandcli
{
class ExitCommand : public ExecutableCommand
{
public:
    [[nodiscard]] bool execute(
        sand::SANDNode &sand_node, std::string &error_message) const override;
    [[nodiscard]] bool should_terminate_program_after_execution() const override;
};
}  // namespace sandcli

#endif  // SANDCLI_EXITCOMMAND_HPP_
