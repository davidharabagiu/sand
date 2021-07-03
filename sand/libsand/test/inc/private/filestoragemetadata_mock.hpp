#ifndef SAND_TEST_FILESTORAGEMETADATA_MOCK_HPP_
#define SAND_TEST_FILESTORAGEMETADATA_MOCK_HPP_

#include <gmock/gmock.h>

#include "filestoragemetadata.hpp"

using namespace ::sand::storage;

class FileStorageMetadataMock : public FileStorageMetadata
{
public:
    MOCK_METHOD(bool, contains, (const std::string &), (const, override));
    MOCK_METHOD(std::string, get_file_path, (const std::string &), (const, override));
    MOCK_METHOD(std::string, add, (const std::string &, const std::string &), (override));
    MOCK_METHOD(bool, remove, (const std::string &), (override));
};

#endif  // SAND_TEST_FILESTORAGEMETADATA_MOCK_HPP_
