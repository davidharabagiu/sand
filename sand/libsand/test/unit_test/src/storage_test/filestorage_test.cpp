#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>

#include "filestorageimpl.hpp"
#include "random.hpp"

#include "filestoragemetadata_mock.hpp"

using namespace ::testing;
using namespace ::sand::storage;
using namespace ::sand::utils;

namespace
{
class FileStorageTest : public Test
{
protected:
    void SetUp() override
    {
        storage_metadata_ = std::make_shared<NiceMock<FileStorageMetadataMock>>();
    }

    void create_test_file(const std::string &file_name, size_t size)
    {
        std::ofstream fs {file_name, std::ios::binary};
        char          byte;
        for (size_t i = 0; i != size; ++i)
        {
            byte = rng_.next<char>();
            fs.write(&byte, 1);
        }
    }

    std::vector<uint8_t> create_test_buffer(size_t size)
    {
        std::vector<uint8_t> ret(size);
        std::generate(ret.begin(), ret.end(), [&] { return rng_.next<uint8_t>(); });
        return ret;
    }

    std::shared_ptr<FileStorageMetadataMock> storage_metadata_;
    Random                                   rng_;
};
}  // namespace

TEST_F(FileStorageTest, Contains)
{
    const std::string file_hash_1 = "file_hash_1";
    const std::string file_hash_2 = "file_hash_2";

    ON_CALL(*storage_metadata_, contains(file_hash_1)).WillByDefault(Return(true));
    ON_CALL(*storage_metadata_, contains(file_hash_2)).WillByDefault(Return(false));

    FileStorageImpl storage {storage_metadata_};
    EXPECT_TRUE(storage.contains(file_hash_1));
    EXPECT_FALSE(storage.contains(file_hash_2));
}

TEST_F(FileStorageTest, ReadFile)
{
    const std::string file_hash   = "file_hash";
    const std::string file_name   = "FileStorageTest_ReadFile_dummy.bin";
    const size_t      file_size   = 1024;
    const size_t      read_offset = 300;
    const size_t      read_size   = 200;

    create_test_file(file_name, file_size);
    ON_CALL(*storage_metadata_, get_file_path(file_hash)).WillByDefault(Return(file_name));

    FileStorageImpl storage {storage_metadata_};

    auto handle = storage.open_file_for_reading(file_hash);
    EXPECT_NE(handle, FileStorage::invalid_handle);

    std::vector<uint8_t> read_file_content(read_size);
    EXPECT_EQ(
        storage.read_file(handle, read_offset, read_size, read_file_content.data()), read_size);

    EXPECT_TRUE(storage.close_file(handle));

    std::vector<uint8_t> expected_file_content(read_size);
    {
        std::ifstream fs {file_name, std::ios::binary};
        fs.seekg(read_offset, std::ios::beg);
        fs.read(reinterpret_cast<char *>(expected_file_content.data()), read_size);
    }

    ASSERT_THAT(read_file_content, ContainerEq(expected_file_content));

    std::filesystem::remove(file_name);
}

TEST_F(FileStorageTest, ReadFile_FileLimitPartlyExceeded)
{
    const std::string file_hash   = "file_hash";
    const std::string file_name   = "FileStorageTest_ReadFile_FileLimitPartlyExceeded_dummy.bin";
    const size_t      file_size   = 1024;
    const size_t      read_offset = 1000;
    const size_t      read_size   = 200;

    create_test_file(file_name, file_size);
    ON_CALL(*storage_metadata_, get_file_path(file_hash)).WillByDefault(Return(file_name));

    FileStorageImpl storage {storage_metadata_};

    auto handle = storage.open_file_for_reading(file_hash);
    EXPECT_NE(handle, FileStorage::invalid_handle);

    std::vector<uint8_t> read_file_content(read_size);
    EXPECT_EQ(storage.read_file(handle, read_offset, read_size, read_file_content.data()),
        file_size - read_offset);
    read_file_content.resize(file_size - read_offset);

    EXPECT_TRUE(storage.close_file(handle));

    std::vector<uint8_t> expected_file_content(read_file_content.size());
    {
        std::ifstream fs {file_name, std::ios::binary};
        fs.seekg(read_offset, std::ios::beg);
        fs.read(reinterpret_cast<char *>(expected_file_content.data()),
            std::streamsize(expected_file_content.size()));
    }

    ASSERT_THAT(read_file_content, ContainerEq(expected_file_content));

    std::filesystem::remove(file_name);
}

TEST_F(FileStorageTest, ReadFile_FileLimitFullyExceeded)
{
    const std::string file_hash   = "file_hash";
    const std::string file_name   = "FileStorageTest_ReadFile_FileLimitFullyExceeded_dummy.bin";
    const size_t      file_size   = 1024;
    const size_t      read_offset = 1024;
    const size_t      read_size   = 200;

    create_test_file(file_name, file_size);
    ON_CALL(*storage_metadata_, get_file_path(file_hash)).WillByDefault(Return(file_name));

    FileStorageImpl storage {storage_metadata_};

    auto handle = storage.open_file_for_reading(file_hash);
    EXPECT_NE(handle, FileStorage::invalid_handle);

    std::vector<uint8_t> read_file_content(read_size);
    EXPECT_EQ(storage.read_file(handle, read_offset, read_size, read_file_content.data()), 0);

    EXPECT_TRUE(storage.close_file(handle));

    std::filesystem::remove(file_name);
}

TEST_F(FileStorageTest, ReadFile_InvalidFileHash)
{
    const std::string file_hash = "file_hash";

    ON_CALL(*storage_metadata_, get_file_path(file_hash)).WillByDefault(Return(""));

    FileStorageImpl storage {storage_metadata_};

    auto handle = storage.open_file_for_reading(file_hash);
    EXPECT_EQ(handle, FileStorage::invalid_handle);
}

TEST_F(FileStorageTest, ReadFile_InvalidHandle)
{
    const size_t data_size = 16;

    FileStorageImpl storage {storage_metadata_};
    uint8_t         data[data_size];
    EXPECT_EQ(storage.read_file(10, 0, data_size, data), 0);
}

TEST_F(FileStorageTest, WriteFile_NewFile)
{
    const std::string          file_hash    = "file_hash";
    const std::string          file_name    = "FileStorageTest_WriteFile_NewFile_dummy.bin";
    const size_t               file_size    = 1024;
    const size_t               write_offset = 300;
    const size_t               write_size   = 200;
    const std::vector<uint8_t> test_data    = create_test_buffer(write_size);

    ON_CALL(*storage_metadata_, add(file_hash, file_name)).WillByDefault(Return(file_name));

    FileStorageImpl storage {storage_metadata_};

    auto handle = storage.open_file_for_writing(file_hash, file_name, file_size, false);
    EXPECT_NE(handle, FileStorage::invalid_handle);
    EXPECT_EQ(storage.write_file(handle, write_offset, write_size, test_data.data()), write_size);
    EXPECT_TRUE(storage.close_file(handle));

    std::vector<uint8_t> file_content(file_size);
    {
        std::ifstream fs {file_name, std::ios::binary};
        fs.seekg(0, std::ios::end);
        EXPECT_EQ(fs.tellg(), file_size);
        fs.seekg(0, std::ios::beg);
        fs.read(reinterpret_cast<char *>(file_content.data()), file_size);
    }

    std::vector<uint8_t> expected_file_content(file_size, 0);
    std::copy(test_data.cbegin(), test_data.cend(), expected_file_content.data() + write_offset);

    ASSERT_THAT(file_content, ContainerEq(expected_file_content));

    std::filesystem::remove(file_name);
}

TEST_F(FileStorageTest, WriteFile_NoTruncate)
{
    const std::string          file_hash    = "file_hash";
    const std::string          file_name    = "FileStorageTest_WriteFile_NoTruncate_dummy.bin";
    const size_t               file_size    = 1024;
    const size_t               write_offset = 300;
    const size_t               write_size   = 200;
    const std::vector<uint8_t> test_data    = create_test_buffer(write_size);
    create_test_file(file_name, file_size);

    std::vector<uint8_t> initial_file_content(file_size);
    {
        std::ifstream fs {file_name, std::ios::binary};
        fs.read(reinterpret_cast<char *>(initial_file_content.data()), file_size);
    }

    ON_CALL(*storage_metadata_, add(file_hash, file_name)).WillByDefault(Return(file_name));

    FileStorageImpl storage {storage_metadata_};

    auto handle = storage.open_file_for_writing(file_hash, file_name, file_size, false);
    EXPECT_NE(handle, FileStorage::invalid_handle);
    EXPECT_EQ(storage.write_file(handle, write_offset, write_size, test_data.data()), write_size);
    EXPECT_TRUE(storage.close_file(handle));

    std::vector<uint8_t> file_content(file_size);
    {
        std::ifstream fs {file_name, std::ios::binary};
        fs.seekg(0, std::ios::end);
        EXPECT_EQ(fs.tellg(), file_size);
        fs.seekg(0, std::ios::beg);
        fs.read(reinterpret_cast<char *>(file_content.data()), file_size);
    }

    std::vector<uint8_t> expected_file_content(initial_file_content);
    std::copy(test_data.cbegin(), test_data.cend(), expected_file_content.data() + write_offset);

    ASSERT_THAT(file_content, ContainerEq(expected_file_content));

    std::filesystem::remove(file_name);
}

TEST_F(FileStorageTest, WriteFile_NoTruncate_IncreaseFileSize)
{
    const std::string file_hash = "file_hash";
    const std::string file_name = "FileStorageTest_WriteFile_NoTruncate_IncreaseFileSize_dummy.bin";
    const size_t      file_size = 1024;
    const size_t      new_file_size      = 2048;
    const size_t      write_offset       = 300;
    const size_t      write_size         = 200;
    const std::vector<uint8_t> test_data = create_test_buffer(write_size);
    create_test_file(file_name, file_size);

    std::vector<uint8_t> initial_file_content(file_size);
    {
        std::ifstream fs {file_name, std::ios::binary};
        fs.read(reinterpret_cast<char *>(initial_file_content.data()), file_size);
    }

    ON_CALL(*storage_metadata_, add(file_hash, file_name)).WillByDefault(Return(file_name));

    FileStorageImpl storage {storage_metadata_};

    auto handle = storage.open_file_for_writing(file_hash, file_name, new_file_size, false);
    EXPECT_NE(handle, FileStorage::invalid_handle);
    EXPECT_EQ(storage.write_file(handle, write_offset, write_size, test_data.data()), write_size);
    EXPECT_TRUE(storage.close_file(handle));

    std::vector<uint8_t> file_content(new_file_size);
    {
        std::ifstream fs {file_name, std::ios::binary};
        fs.seekg(0, std::ios::end);
        EXPECT_EQ(fs.tellg(), new_file_size);
        fs.seekg(0, std::ios::beg);
        fs.read(reinterpret_cast<char *>(file_content.data()), new_file_size);
    }

    std::vector<uint8_t> expected_file_content(new_file_size, 0);
    std::copy(
        initial_file_content.cbegin(), initial_file_content.cend(), expected_file_content.begin());
    std::copy(test_data.cbegin(), test_data.cend(), expected_file_content.data() + write_offset);

    ASSERT_THAT(file_content, ContainerEq(expected_file_content));

    std::filesystem::remove(file_name);
}

TEST_F(FileStorageTest, WriteFile_NoTruncate_ReduceFileSize)
{
    const std::string file_hash = "file_hash";
    const std::string file_name = "FileStorageTest_WriteFile_NoTruncate_ReduceFileSize_dummy.bin";
    const size_t      file_size = 1024;
    const size_t      new_file_size      = 512;
    const size_t      write_offset       = 300;
    const size_t      write_size         = 200;
    const std::vector<uint8_t> test_data = create_test_buffer(write_size);
    create_test_file(file_name, file_size);

    std::vector<uint8_t> initial_file_content(file_size);
    {
        std::ifstream fs {file_name, std::ios::binary};
        fs.read(reinterpret_cast<char *>(initial_file_content.data()), file_size);
    }

    ON_CALL(*storage_metadata_, add(file_hash, file_name)).WillByDefault(Return(file_name));

    FileStorageImpl storage {storage_metadata_};

    auto handle = storage.open_file_for_writing(file_hash, file_name, new_file_size, false);
    EXPECT_NE(handle, FileStorage::invalid_handle);
    EXPECT_EQ(storage.write_file(handle, write_offset, write_size, test_data.data()), write_size);
    EXPECT_TRUE(storage.close_file(handle));

    std::vector<uint8_t> file_content(new_file_size);
    {
        std::ifstream fs {file_name, std::ios::binary};
        fs.seekg(0, std::ios::end);
        EXPECT_EQ(fs.tellg(), new_file_size);
        fs.seekg(0, std::ios::beg);
        fs.read(reinterpret_cast<char *>(file_content.data()), new_file_size);
    }

    std::vector<uint8_t> expected_file_content(initial_file_content);
    expected_file_content.resize(new_file_size);
    std::copy(test_data.cbegin(), test_data.cend(), expected_file_content.data() + write_offset);

    ASSERT_THAT(file_content, ContainerEq(expected_file_content));

    std::filesystem::remove(file_name);
}

TEST_F(FileStorageTest, WriteFile_Truncate)
{
    const std::string          file_hash    = "file_hash";
    const std::string          file_name    = "FileStorageTest_WriteFile_Truncate_dummy.bin";
    const size_t               file_size    = 1024;
    const size_t               write_offset = 300;
    const size_t               write_size   = 200;
    const std::vector<uint8_t> test_data    = create_test_buffer(write_size);
    create_test_file(file_name, file_size);

    ON_CALL(*storage_metadata_, add(file_hash, file_name)).WillByDefault(Return(file_name));

    FileStorageImpl storage {storage_metadata_};

    auto handle = storage.open_file_for_writing(file_hash, file_name, file_size, true);
    EXPECT_NE(handle, FileStorage::invalid_handle);
    EXPECT_EQ(storage.write_file(handle, write_offset, write_size, test_data.data()), write_size);
    EXPECT_TRUE(storage.close_file(handle));

    std::vector<uint8_t> file_content(file_size);
    {
        std::ifstream fs {file_name, std::ios::binary};
        fs.seekg(0, std::ios::end);
        EXPECT_EQ(fs.tellg(), file_size);
        fs.seekg(0, std::ios::beg);
        fs.read(reinterpret_cast<char *>(file_content.data()), file_size);
    }

    std::vector<uint8_t> expected_file_content(file_size, 0);
    std::copy(test_data.cbegin(), test_data.cend(), expected_file_content.data() + write_offset);

    ASSERT_THAT(file_content, ContainerEq(expected_file_content));

    std::filesystem::remove(file_name);
}

TEST_F(FileStorageTest, WriteFile_FileLimitPartlyExceeded)
{
    const std::string file_hash    = "file_hash";
    const std::string file_name    = "FileStorageTest_WriteFile_FileLimitPartlyExceeded_dummy.bin";
    const size_t      file_size    = 1024;
    const size_t      write_offset = 1000;
    const size_t      write_size   = 200;
    const std::vector<uint8_t> test_data = create_test_buffer(write_size);

    ON_CALL(*storage_metadata_, add(file_hash, file_name)).WillByDefault(Return(file_name));

    FileStorageImpl storage {storage_metadata_};

    auto handle = storage.open_file_for_writing(file_hash, file_name, file_size, false);
    EXPECT_NE(handle, FileStorage::invalid_handle);
    EXPECT_EQ(storage.write_file(handle, write_offset, write_size, test_data.data()),
        file_size - write_offset);
    EXPECT_TRUE(storage.close_file(handle));

    std::vector<uint8_t> file_content(file_size);
    {
        std::ifstream fs {file_name, std::ios::binary};
        fs.seekg(0, std::ios::end);
        EXPECT_EQ(fs.tellg(), file_size);
        fs.seekg(0, std::ios::beg);
        fs.read(reinterpret_cast<char *>(file_content.data()), file_size);
    }

    std::vector<uint8_t> expected_file_content(file_size, 0);
    std::copy_n(
        test_data.cbegin(), file_size - write_offset, expected_file_content.data() + write_offset);

    ASSERT_THAT(file_content, ContainerEq(expected_file_content));

    std::filesystem::remove(file_name);
}

TEST_F(FileStorageTest, WriteFile_FileLimitFullyExceeded)
{
    const std::string file_hash    = "file_hash";
    const std::string file_name    = "FileStorageTest_WriteFile_FileLimitFullyExceeded_dummy.bin";
    const size_t      file_size    = 1024;
    const size_t      write_offset = 1024;
    const size_t      write_size   = 200;
    const std::vector<uint8_t> test_data = create_test_buffer(write_size);

    ON_CALL(*storage_metadata_, add(file_hash, file_name)).WillByDefault(Return(file_name));

    FileStorageImpl storage {storage_metadata_};

    auto handle = storage.open_file_for_writing(file_hash, file_name, file_size, false);
    EXPECT_NE(handle, FileStorage::invalid_handle);
    EXPECT_EQ(storage.write_file(handle, write_offset, write_size, test_data.data()), 0);
    EXPECT_TRUE(storage.close_file(handle));

    std::vector<uint8_t> file_content(file_size);
    {
        std::ifstream fs {file_name, std::ios::binary};
        fs.seekg(0, std::ios::end);
        EXPECT_EQ(fs.tellg(), file_size);
        fs.seekg(0, std::ios::beg);
        fs.read(reinterpret_cast<char *>(file_content.data()), file_size);
    }

    ASSERT_THAT(file_content, Each(0));

    std::filesystem::remove(file_name);
}

TEST_F(FileStorageTest, WriteFile_CannotAddFileToMetadata)
{
    const std::string file_hash = "file_hash";
    const std::string file_name = "FileStorageTest_WriteFile_CannotAddFileToMetadata_dummy.bin";
    const size_t      file_size = 1024;

    ON_CALL(*storage_metadata_, add(file_hash, file_name)).WillByDefault(Return(""));

    FileStorageImpl storage {storage_metadata_};

    auto handle = storage.open_file_for_writing(file_hash, file_name, file_size, false);
    EXPECT_EQ(handle, FileStorage::invalid_handle);
}

TEST_F(FileStorageTest, WriteFile_InvalidFileHandle)
{
    const size_t  data_size = 16;
    const uint8_t data[data_size] {};

    FileStorageImpl storage {storage_metadata_};
    EXPECT_EQ(storage.write_file(10, 0, data_size, data), 0);
}

TEST_F(FileStorageTest, DeleteClosedFile)
{
    const std::string          file_hash = "file_hash";
    const std::string          file_name = "FileStorageTest_DeleteClosedFile_dummy.bin";
    const size_t               file_size = 16;
    const std::vector<uint8_t> test_data = create_test_buffer(file_size);

    ON_CALL(*storage_metadata_, add(file_hash, file_name)).WillByDefault(Return(file_name));
    ON_CALL(*storage_metadata_, get_file_path(file_hash)).WillByDefault(Return(file_name));
    EXPECT_CALL(*storage_metadata_, remove(file_hash)).Times(1).WillOnce(Return(true));

    FileStorageImpl storage {storage_metadata_};

    auto handle = storage.open_file_for_writing(file_hash, file_name, file_size, false);
    EXPECT_NE(handle, FileStorage::invalid_handle);
    EXPECT_EQ(storage.write_file(handle, 0, file_size, test_data.data()), file_size);
    EXPECT_TRUE(storage.close_file(handle));

    EXPECT_TRUE(storage.delete_file(file_hash));
    EXPECT_FALSE(std::filesystem::exists(file_name));
}

TEST_F(FileStorageTest, DeleteOpenFile)
{
    const std::string          file_hash = "file_hash";
    const std::string          file_name = "FileStorageTest_DeleteOpenFile_dummy.bin";
    const size_t               file_size = 16;
    const std::vector<uint8_t> test_data = create_test_buffer(file_size);

    ON_CALL(*storage_metadata_, add(file_hash, file_name)).WillByDefault(Return(file_name));
    ON_CALL(*storage_metadata_, get_file_path(file_hash)).WillByDefault(Return(file_name));
    EXPECT_CALL(*storage_metadata_, remove(file_hash)).Times(1).WillOnce(Return(true));

    FileStorageImpl storage {storage_metadata_};

    auto handle = storage.open_file_for_writing(file_hash, file_name, file_size, false);
    EXPECT_NE(handle, FileStorage::invalid_handle);
    EXPECT_EQ(storage.write_file(handle, 0, file_size, test_data.data()), file_size);

    EXPECT_TRUE(storage.delete_file(file_hash));
    EXPECT_FALSE(std::filesystem::exists(file_name));

    EXPECT_EQ(storage.write_file(handle, 0, file_size, test_data.data()), 0);
}
