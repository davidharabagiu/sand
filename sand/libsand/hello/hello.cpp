#include "sand/hello.hpp"

#include <iomanip>
#include <iostream>
#include <sstream>

#include <cstring>

#include <glog/logging.h>
#include <openssl/sha.h>

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

    const char *  data = "test";
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512(reinterpret_cast<const unsigned char *>(data), std::strlen(data), hash);

    std::ostringstream ss;
    for (auto byte : hash)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << unsigned {byte};
    }
    LOG(INFO) << ss.str();
}
