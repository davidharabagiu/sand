#ifndef SANDCLI_GETFILECOMMAND_HPP_
#define SANDCLI_GETFILECOMMAND_HPP_

#include "executablecommand.hpp"

namespace sandcli
{
class GetFileCommand : public ExecutableCommand
{
public:
    GetFileCommand(std::string file_hash, std::string file_name);
    [[nodiscard]] bool execute(
        sand::SANDNode &sand_node, std::string &error_message) const override;
    [[nodiscard]] bool should_terminate_program_after_execution() const override;

private:
    std::string file_hash_;
    std::string file_name_;
};
}  // namespace sandcli

#endif  // SANDCLI_GETFILECOMMAND_HPP_
