#include "sand/hello.hpp"

#include <iostream>

#include <glog/logging.h>

SAND_API_CTOR void init()
{
}

SAND_API_DTOR void uninit()
{
    LOG(INFO) << "Unloading libsand";
}

void sand::LogSomething()
{
    LOG(INFO) << "Hello";
}
