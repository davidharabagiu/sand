#include <iostream>

#include <glog/logging.h>

#include <sand/hello.hpp>

int main(int /*argc*/, char **argv)
{
    google::InitGoogleLogging(argv[0]);
    LOG(INFO) << "sandcli started";

    sand::LogSomething();

    return 0;
}
