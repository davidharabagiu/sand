#ifndef SAND_TEST_FILESTORAGE_MOCK_HPP_
#define SAND_TEST_FILESTORAGE_MOCK_HPP_

#include <gmock/gmock.h>

#include "filestorage.hpp"

using namespace ::sand::storage;

class FileStorageMock : public FileStorage
{
public:
    MOCK_METHOD(bool, contains, (const std::string &), (const, override));
};

#endif  // SAND_TEST_FILESTORAGE_MOCK_HPP_
