#include "getfilecommand.hpp"

#include <memory>

#include "sandnode.hpp"

namespace sandcli
{
GetFileCommand::GetFileCommand(std::string file_hash, std::string file_name)
    : file_hash_ {std::move(file_hash)}
    , file_name_ {std::move(file_name)}
{}

bool GetFileCommand::execute(sand::SANDNode &sand_node, std::string &error_message) const
{
    return sand_node.download_file(file_hash_, file_name_, error_message);
}

bool GetFileCommand::should_terminate_program_after_execution() const
{
    return false;
}
}  // namespace sandcli
