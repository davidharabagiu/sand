#include "commandreader.hpp"

#include <regex>
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
        if (!std::getline(input_, input_line))
        {
            return {};
        }
    } while (input_line.empty());

    std::string              cmd;
    std::vector<std::string> args;
    std::string              token;

    std::regex                 line_split_rgx {"\\s+"};
    std::sregex_token_iterator line_token_it {
        input_line.cbegin(), input_line.cend(), line_split_rgx, -1};
    std::sregex_token_iterator line_token_it_end;
    cmd = *line_token_it++;
    for (; line_token_it != line_token_it_end; ++line_token_it)
    {
        args.push_back(*line_token_it);
    }

    return {cmd, args.cbegin(), args.cend()};
}
}  // namespace sandcli
