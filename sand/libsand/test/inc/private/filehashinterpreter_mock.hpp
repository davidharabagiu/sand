#ifndef SAND_TEST_FILEHASHINTERPRETER_MOCK_HPP_
#define SAND_TEST_FILEHASHINTERPRETER_MOCK_HPP_

#include <gmock/gmock.h>

#include "filehashinterpreter.hpp"

using namespace ::sand::storage;
using namespace ::sand::protocol;
using namespace ::sand::utils;

class FileHashInterpreterMock : public FileHashInterpreter
{
public:
    MOCK_METHOD(bool, decode, (const std::string &, AHash &), (const, override));
    MOCK_METHOD(std::string, encode, (const AHash &), (const, override));
    MOCK_METHOD(size_t, get_file_size, (const AHash &), (const, override));
    MOCK_METHOD(std::future<bool>, create_hash, (const std::string &, AHash &, Executer &),
        (const, override));
};

#endif  // SAND_TEST_FILEHASHINTERPRETER_MOCK_HPP_
