#include "commandreader.hpp"

#include <sstream>

namespace sandcli
{
CommandReader::CommandReader(std::istream &input)
    : input_ {input}
{}

Command CommandReader::read_next_command() const
{
    std::string input_line;
    do
    {
        std::getline(input_, input_line);
    } while (input_line.empty());

    std::istringstream       ss {input_line};
    std::string              cmd;
    std::vector<std::string> args;
    std::string              token;

    std::getline(ss, cmd);

    while (std::getline(ss, token))
    {
        args.push_back(std::move(token));
    }

    return {cmd, args.cbegin(), args.cend()};
}
}  // namespace sandcli
