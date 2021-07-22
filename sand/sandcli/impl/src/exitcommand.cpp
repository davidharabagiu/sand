#include "exitcommand.hpp"

#include "sandnode.hpp"

namespace sandcli
{
bool ExitCommand::execute(sand::SANDNode &sand_node, std::string &error_message) const
{
    bool status = sand_node.stop();
    if (!status)
    {
        error_message = "Internal error: cleanup failed";
    }
    return status;
}

bool ExitCommand::should_terminate_program_after_execution() const
{
    return true;
}
}  // namespace sandcli
