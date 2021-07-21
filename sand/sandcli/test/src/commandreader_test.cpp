#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <sstream>
#include <string>

#include "commandreader.hpp"

using namespace ::testing;
using namespace ::sandcli;

TEST(CommandReaderTest, EmptyInputStream)
{
    std::string        commands = "";
    std::istringstream commands_stream {commands};
    CommandReader      command_reader {commands_stream};
    EXPECT_FALSE(command_reader.read_next_command().valid());
}

TEST(CommandReaderTest, SimpleCommands)
{
    std::string        commands = "cmd1\ncmd2\ncmd3";
    std::istringstream commands_stream {commands};
    CommandReader      command_reader {commands_stream};

    Command c1 = command_reader.read_next_command();
    EXPECT_TRUE(c1.valid());
    EXPECT_EQ(c1.cmd, "cmd1");
    EXPECT_EQ(c1.args.size(), 0);

    Command c2 = command_reader.read_next_command();
    EXPECT_TRUE(c2.valid());
    EXPECT_EQ(c2.cmd, "cmd2");
    EXPECT_EQ(c2.args.size(), 0);

    Command c3 = command_reader.read_next_command();
    EXPECT_TRUE(c3.valid());
    EXPECT_EQ(c3.cmd, "cmd3");
    EXPECT_EQ(c3.args.size(), 0);

    EXPECT_FALSE(command_reader.read_next_command().valid());
}

TEST(CommandReaderTest, CommandsWithArgs)
{
    std::string        commands = "cmd1 arg1\ncmd2 arg1 arg2 arg3";
    std::istringstream commands_stream {commands};
    CommandReader      command_reader {commands_stream};

    Command c1 = command_reader.read_next_command();
    EXPECT_TRUE(c1.valid());
    EXPECT_EQ(c1.cmd, "cmd1");
    EXPECT_THAT(c1.args, ElementsAre("arg1"));

    Command c2 = command_reader.read_next_command();
    EXPECT_TRUE(c2.valid());
    EXPECT_EQ(c2.cmd, "cmd2");
    EXPECT_THAT(c2.args, ElementsAre("arg1", "arg2", "arg3"));

    EXPECT_FALSE(command_reader.read_next_command().valid());
}
