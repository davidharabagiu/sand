#include <gtest/gtest.h>

#include "commandinterpreter.hpp"
#include "exitcommand.hpp"
#include "getfilecommand.hpp"

using namespace ::sandcli;

TEST(CommandInterpreterTest, InvalidCommandObject)
{
    CommandInterpreter command_interpreter;

    std::string err;
    EXPECT_EQ(command_interpreter.interpret(Command {}, err), nullptr);
    EXPECT_FALSE(err.empty());
}

TEST(CommandInterpreterTest, UnknownCommand)
{
    CommandInterpreter command_interpreter;

    std::string err;
    EXPECT_EQ(command_interpreter.interpret(Command {"plm"}, err), nullptr);
    EXPECT_FALSE(err.empty());
}

TEST(CommandInterpreterTest, ExitCommand)
{
    CommandInterpreter command_interpreter;

    std::string err;
    auto        cmd = command_interpreter.interpret(Command {"exit"}, err);
    EXPECT_NE(cmd, nullptr);
    EXPECT_NE(dynamic_cast<ExitCommand *>(cmd.get()), nullptr);
    EXPECT_TRUE(err.empty());
}

TEST(CommandInterpreterTest, ExitCommand_InvalidNumberOfArgs)
{
    CommandInterpreter command_interpreter;
    const std::vector  args {"arg1", "arg2"};

    std::string err;
    EXPECT_EQ(
        command_interpreter.interpret(Command {"exit", args.begin(), args.end()}, err), nullptr);
    EXPECT_FALSE(err.empty());
}

TEST(CommandInterpreterTest, GetFileCommand)
{
    CommandInterpreter command_interpreter;
    const std::vector  args {"1234", "manea.mp3"};

    std::string err;
    auto        cmd = command_interpreter.interpret(Command {"get", args.begin(), args.end()}, err);
    EXPECT_NE(cmd, nullptr);
    EXPECT_NE(dynamic_cast<GetFileCommand *>(cmd.get()), nullptr);
    EXPECT_TRUE(err.empty());
}

TEST(CommandInterpreterTest, GetFileCommand_InvalidNumberOfArgs)
{
    CommandInterpreter command_interpreter;
    const std::vector  args {"1234"};

    std::string err;
    EXPECT_EQ(
        command_interpreter.interpret(Command {"get", args.begin(), args.end()}, err), nullptr);
    EXPECT_FALSE(err.empty());
}
