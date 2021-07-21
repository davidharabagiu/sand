#ifndef SANDCLI_EXITCOMMAND_HPP_
#define SANDCLI_EXITCOMMAND_HPP_

#include <string>

#include "executablecommand.hpp"

namespace sandcli
{
class ExitCommand : public ExecutableCommand
{
public:
    void execute(sand::SANDNode &sand_node) const override;
};
}  // namespace sandcli

#endif  // SANDCLI_EXITCOMMAND_HPP_
