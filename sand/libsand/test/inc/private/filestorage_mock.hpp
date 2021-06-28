#ifndef SAND_TEST_FILESTORAGE_MOCK_HPP_
#define SAND_TEST_FILESTORAGE_MOCK_HPP_

#include <gmock/gmock.h>

#include "filestorage.hpp"

using namespace ::sand::storage;

class FileStorageMock : public FileStorage
{
public:
    MOCK_METHOD(bool, contains, (const std::string &), (const, override));
    MOCK_METHOD(Handle, open_file_for_reading, (const std::string &), (override));
    MOCK_METHOD(Handle, open_file_for_writing,
        (const std::string &, const std::string &, size_t, bool), (override));
    MOCK_METHOD(bool, read_file, (Handle, size_t, size_t, uint8_t *), (override));
    MOCK_METHOD(bool, write_file, (Handle, size_t, size_t, const uint8_t *), (override));
    MOCK_METHOD(bool, close_file, (Handle), (override));
    MOCK_METHOD(bool, delete_file, (const std::string &), (override));
};

#endif  // SAND_TEST_FILESTORAGE_MOCK_HPP_
