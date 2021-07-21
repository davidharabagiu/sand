#ifndef SANDCLI_COMMANDREADER_HPP_
#define SANDCLI_COMMANDREADER_HPP_

#include <istream>
#include <string>
#include <vector>

#include "command.hpp"

namespace sandcli
{
class CommandReader
{
public:
    explicit CommandReader(std::istream &input);
    [[nodiscard]] Command read_next_command() const;

private:
    std::istream &input_;
};
}  // namespace sandcli

#endif  // SANDCLI_COMMANDREADER_HPP_
