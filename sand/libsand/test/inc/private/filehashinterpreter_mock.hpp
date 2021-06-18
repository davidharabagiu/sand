#ifndef SAND_TEST_FILEHASHINTERPRETER_MOCK_HPP_
#define SAND_TEST_FILEHASHINTERPRETER_MOCK_HPP_

#include <gmock/gmock.h>

#include "filehashinterpreter.hpp"

using namespace ::sand::storage;
using namespace ::sand::protocol;

class FileHashInterpreterMock : public FileHashInterpreter
{
public:
    MOCK_METHOD((std::pair<AHash, bool>), decode, (const std::string &), (const, override));
    MOCK_METHOD(std::string, encode, (const AHash &), (const, override));
    MOCK_METHOD(size_t, get_file_size, (const AHash &), (const, override));
};

#endif  // SAND_TEST_FILEHASHINTERPRETER_MOCK_HPP_