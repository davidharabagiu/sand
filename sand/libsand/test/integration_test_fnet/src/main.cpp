#include <gtest/gtest.h>

#include <glog/logging.h>

#include "sandversion.hpp"

int main(int argc, char **argv)
{
    ::google::InitGoogleLogging(argv[0]);
    FLAGS_logtostderr = true;

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

TEST(Test, PrintVersion)
{
    LOG(INFO) << "Testing SAND library version " << sand::sand_version;
}
