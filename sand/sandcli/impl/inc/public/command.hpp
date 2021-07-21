#ifndef SANDCLI_COMMAND_HPP_
#define SANDCLI_COMMAND_HPP_

#include <memory>
#include <string>
#include <type_traits>
#include <vector>

namespace sandcli
{
struct Command
{
    Command() = default;

    template<typename ArgsIt,
        typename = std::enable_if_t<std::is_convertible_v<decltype(*ArgsIt {}), std::string>>>
    Command(std::string _cmd, ArgsIt args_begin, ArgsIt args_end)
        : cmd {std::move(_cmd)}
        , args(args_begin, args_end)
    {}

    Command(const Command &other) = default;
    Command &operator=(const Command &rhs) = default;

    Command(Command &&other) noexcept
        : cmd {std::move(other.cmd)}
        , args {std::move(other.args)}
    {}

    Command &operator=(Command &&rhs) noexcept
    {
        cmd  = std::move(rhs.cmd);
        args = std::move(rhs.args);
        return *this;
    }

    [[nodiscard]] bool valid() const
    {
        return !cmd.empty();
    }

    explicit operator bool() const
    {
        return valid();
    }

    std::string              cmd;
    std::vector<std::string> args;
};
}  // namespace sandcli

#endif  // SANDCLI_COMMAND_HPP_
