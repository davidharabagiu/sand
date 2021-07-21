#include "getfilecommand.hpp"

#include <memory>

#include "sandnode.hpp"

namespace sandcli
{
GetFileCommand::GetFileCommand(std::string file_hash, std::string file_name)
    : file_hash_ {std::move(file_hash)}
    , file_name_ {std::move(file_name)}
{}

void GetFileCommand::execute(sand::SANDNode & /*sand_node*/) const
{}
}  // namespace sandcli
