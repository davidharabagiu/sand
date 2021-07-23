#include <gtest/gtest.h>

#include "datasizeformatter.hpp"

using namespace ::sandcli;

TEST(DataSizeFormatterTest, B)
{
    EXPECT_EQ(DataSizeFormatter {}.format(123, 3, 3), "123 B");
}

TEST(DataSizeFormatterTest, KiB)
{
    EXPECT_EQ(DataSizeFormatter {}.format(1234, 3, 3), "1.205 KiB");
}

TEST(DataSizeFormatterTest, MiB)
{
    EXPECT_EQ(DataSizeFormatter {}.format(12345678, 3, 3), "11.774 MiB");
}

TEST(DataSizeFormatterTest, GiB)
{
    EXPECT_EQ(DataSizeFormatter {}.format(123456789012, 3, 3), "114.978 GiB");
}

TEST(DataSizeFormatterTest, TiB)
{
    EXPECT_EQ(DataSizeFormatter {}.format(1234567890123, 3, 3), "1.123 TiB");
}

TEST(DataSizeFormatterTest, PiB)
{
    EXPECT_EQ(DataSizeFormatter {}.format(12345678901234567, 3, 3), "10.965 PiB");
}

TEST(DataSizeFormatterTest, EiB)
{
    EXPECT_EQ(DataSizeFormatter {}.format(1234567890123456789, 3, 3), "1.071 EiB");
}

TEST(DataSizeFormatterTest, KiB_NoFractionalPart)
{
    EXPECT_EQ(DataSizeFormatter {}.format(1234, 3, 0), "1 KiB");
}

TEST(DataSizeFormatterTest, KiB_NoRemDivision)
{
    EXPECT_EQ(DataSizeFormatter {}.format(1024, 3, 3), "1 KiB");
}
