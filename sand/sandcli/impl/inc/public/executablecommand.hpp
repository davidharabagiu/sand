#ifndef SANDCLI_EXECUTABLECOMMAND_HPP_
#define SANDCLI_EXECUTABLECOMMAND_HPP_

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
    virtual ~ExecutableCommand() = 0;

    virtual void execute(sand::SANDNode &sand_node) const = 0;
};
}  // namespace sandcli

#endif  // SANDCLI_EXECUTABLECOMMAND_HPP_
