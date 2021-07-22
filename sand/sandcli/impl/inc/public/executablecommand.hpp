#ifndef SANDCLI_EXECUTABLECOMMAND_HPP_
#define SANDCLI_EXECUTABLECOMMAND_HPP_

#include <string>

namespace sand
{
// Forward declarations
class SANDNode;
}  // namespace sand

namespace sandcli
{
class ExecutableCommand
{
public:
    virtual ~ExecutableCommand() = default;

    [[nodiscard]] virtual bool execute(
        sand::SANDNode &sand_node, std::string &error_message) const            = 0;
    [[nodiscard]] virtual bool should_terminate_program_after_execution() const = 0;
};
}  // namespace sandcli

#endif  // SANDCLI_EXECUTABLECOMMAND_HPP_
