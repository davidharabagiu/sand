#include "sand/hello.hpp"

#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>

#include <glog/logging.h>

#include "mainexecuter.hpp"
#include "rsacipherimpl.hpp"

SAND_API_CTOR void init()
{
}

SAND_API_DTOR void uninit()
{
    LOG(INFO) << "Unloading libsand";
}

void sand::Test()
{
    sand::crypto::RSACipherImpl  rsa;
    sand::crypto::RSACipher::Key pub, pri;
    sand::utils::MainExecuter    executer;

    if (!rsa.generate_key_pair(
                crypto::RSACipher::M4096, crypto::RSACipher::E65537, pub, pri, executer)
             .get())
    {
        LOG(FATAL) << "Cannot generate RSA key pair";
    }

    sand::crypto::RSACipher::ByteVector bytes(10000);
    std::generate(bytes.begin(), bytes.end(), [i = 0]() mutable { return i++; });

    auto encrypted = rsa.encrypt(pub, bytes, executer, 8).get();
    auto decrypted = rsa.decrypt(pri, encrypted, executer, 8).get();
    LOG(INFO) << "done";
}
