#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>

#include <nlohmann/json.hpp>

#include "filestoragemetadataimpl.hpp"
#include "messages.hpp"
#include "testutils.hpp"

#include "executer_mock.hpp"
#include "filehashinterpreter_mock.hpp"

using namespace ::testing;
using namespace ::sand::storage;
using namespace ::sand::utils;
using namespace ::sand::protocol;

namespace
{
class FileStorageMetadataTest : public Test
{
protected:
    void SetUp() override
    {
        file_hash_interpreter_ = new NiceMock<FileHashInterpreterMock>();
        executer_              = std::make_shared<NiceMock<ExecuterMock>>();
    }

    std::unordered_map<std::string, std::string> create_storage(
        const std::string &dir_path, int number_of_files)
    {
        std::filesystem::create_directories(dir_path);
        std::unordered_map<std::string, std::string> files;
        for (int i = 0; i != number_of_files; ++i)
        {
            std::ostringstream ss_file_name;
            ss_file_name << "file" << i;

            std::string file_path {std::filesystem::path {dir_path} / ss_file_name.str()};

            std::ostringstream ss_file_hash_enc;
            ss_file_hash_enc << "hash" << i;

            AHash file_hash_dec {};
            std::copy_n(reinterpret_cast<const char *>(&i), sizeof(i), file_hash_dec.begin());

            ON_CALL(*file_hash_interpreter_, create_hash(file_path, _, _))
                .WillByDefault([file_hash_dec](const auto & /*file_path*/, AHash &out, Executer &) {
                    out = file_hash_dec;
                    return testutils::create_future(true);
                });
            ON_CALL(*file_hash_interpreter_, encode(file_hash_dec))
                .WillByDefault(Return(ss_file_hash_enc.str()));

            files.emplace(ss_file_hash_enc.str(), ss_file_name.str());

            std::ofstream fs {file_path};
        }
        return files;
    }

    static std::unordered_map<std::string, std::string> get_storage_map(
        const std::string &metadata_file)
    {
        std::ifstream fs {metadata_file};
        EXPECT_TRUE(fs);
        nlohmann::json j;
        fs >> j;

        std::unordered_map<std::string, std::string> storage_map;
        for (const auto &e : j)
        {
            EXPECT_TRUE(e.contains("hash"));
            EXPECT_TRUE(e.contains("name"));
            storage_map.emplace(e.at("hash"), e.at("name"));
        }

        return storage_map;
    }

    static void create_metadata_file(
        const std::unordered_map<std::string, std::string> &storage_map,
        const std::string &                                 metadata_file_path)
    {
        nlohmann::json j;
        for (const auto &[hash, name] : storage_map)
        {
            auto &e   = j.emplace_back();
            e["hash"] = hash;
            e["name"] = name;
        }

        std::ofstream fs {metadata_file_path};
        fs << j;
    }

    FileHashInterpreterMock *     file_hash_interpreter_;
    std::shared_ptr<ExecuterMock> executer_;
};
}  // namespace

TEST_F(FileStorageMetadataTest, NewMetadataFile)
{
    const std::string storage_path    = "fake_storage";
    const std::string metadata_file   = "storage_metadata.json";
    const int         number_of_files = 10;

    auto expected_storage_map = create_storage(storage_path, number_of_files);

    {
        FileStorageMetadataImpl fs_meta {
            std::unique_ptr<FileHashInterpreter>(file_hash_interpreter_), executer_, metadata_file,
            storage_path};

        for (const auto &[hash, name] : expected_storage_map)
        {
            EXPECT_TRUE(fs_meta.contains(hash));
            EXPECT_EQ(fs_meta.get_file_path(hash), std::filesystem::path {storage_path} / name);
        }
    }

    auto actual_storage_map = get_storage_map(metadata_file);
    EXPECT_EQ(actual_storage_map.size(), number_of_files);
    ASSERT_THAT(actual_storage_map, ContainerEq(expected_storage_map));

    std::filesystem::remove(metadata_file);
    std::filesystem::remove_all(storage_path);
}

TEST_F(FileStorageMetadataTest, ExistingMetadataFile)
{
    const std::string storage_path    = "fake_storage";
    const std::string metadata_file   = "storage_metadata.json";
    const int         number_of_files = 10;

    auto expected_storage_map = create_storage(storage_path, number_of_files);
    create_metadata_file(expected_storage_map, metadata_file);

    {
        FileStorageMetadataImpl fs_meta {
            std::unique_ptr<FileHashInterpreter>(file_hash_interpreter_), executer_, metadata_file,
            storage_path};

        for (const auto &[hash, name] : expected_storage_map)
        {
            EXPECT_TRUE(fs_meta.contains(hash));
            EXPECT_EQ(fs_meta.get_file_path(hash), std::filesystem::path {storage_path} / name);
        }
    }

    auto actual_storage_map = get_storage_map(metadata_file);
    EXPECT_EQ(actual_storage_map.size(), number_of_files);
    ASSERT_THAT(actual_storage_map, ContainerEq(expected_storage_map));

    std::filesystem::remove(metadata_file);
    std::filesystem::remove_all(storage_path);
}

TEST_F(FileStorageMetadataTest, ExistingMetadataFile_SomeFilesMissing)
{
    const std::string storage_path            = "fake_storage";
    const std::string metadata_file           = "storage_metadata.json";
    const int         number_of_files         = 10;
    const int         number_of_missing_files = 3;

    auto expected_storage_map = create_storage(storage_path, number_of_files);
    create_metadata_file(expected_storage_map, metadata_file);

    std::map<std::string, std::string> missing_files;
    for (auto [it, i] = std::make_pair(expected_storage_map.cbegin(), 0);
         i != number_of_missing_files; ++i, ++it)
    {
        missing_files.emplace(it->first, it->second);
    }
    for (const auto &[h, n] : missing_files)
    {
        expected_storage_map.erase(h);
        std::filesystem::remove(std::filesystem::path {storage_path} / n);
    }

    {
        FileStorageMetadataImpl fs_meta {
            std::unique_ptr<FileHashInterpreter>(file_hash_interpreter_), executer_, metadata_file,
            storage_path};

        for (const auto &[hash, name] : expected_storage_map)
        {
            EXPECT_TRUE(fs_meta.contains(hash));
            EXPECT_EQ(fs_meta.get_file_path(hash), std::filesystem::path {storage_path} / name);
        }

        for (const auto &[hash, name] : missing_files)
        {
            EXPECT_FALSE(fs_meta.contains(hash));
        }
    }

    auto actual_storage_map = get_storage_map(metadata_file);
    EXPECT_EQ(actual_storage_map.size(), number_of_files - number_of_missing_files);
    ASSERT_THAT(actual_storage_map, ContainerEq(expected_storage_map));

    std::filesystem::remove(metadata_file);
    std::filesystem::remove_all(storage_path);
}

TEST_F(FileStorageMetadataTest, ExistingMetadataFile_SomeNewFiles)
{
    const std::string storage_path        = "fake_storage";
    const std::string metadata_file       = "storage_metadata.json";
    const int         number_of_files     = 10;
    const int         number_of_new_files = 3;

    auto expected_storage_map = create_storage(storage_path, number_of_files);
    create_metadata_file(expected_storage_map, metadata_file);

    expected_storage_map = create_storage(storage_path, number_of_files + number_of_new_files);

    {
        FileStorageMetadataImpl fs_meta {
            std::unique_ptr<FileHashInterpreter>(file_hash_interpreter_), executer_, metadata_file,
            storage_path};

        for (const auto &[hash, name] : expected_storage_map)
        {
            EXPECT_TRUE(fs_meta.contains(hash));
            EXPECT_EQ(fs_meta.get_file_path(hash), std::filesystem::path {storage_path} / name);
        }
    }

    auto actual_storage_map = get_storage_map(metadata_file);
    EXPECT_EQ(actual_storage_map.size(), number_of_files + number_of_new_files);
    ASSERT_THAT(actual_storage_map, ContainerEq(expected_storage_map));

    std::filesystem::remove(metadata_file);
    std::filesystem::remove_all(storage_path);
}

TEST_F(FileStorageMetadataTest, AddFile)
{
    const std::string storage_path    = "fake_storage";
    const std::string metadata_file   = "storage_metadata.json";
    const int         number_of_files = 10;
    const std::string new_file_hash   = "new_file_hash";
    const std::string new_file_name   = "new_file_name";

    auto expected_storage_map = create_storage(storage_path, number_of_files);
    create_metadata_file(expected_storage_map, metadata_file);

    {
        FileStorageMetadataImpl fs_meta {
            std::unique_ptr<FileHashInterpreter>(file_hash_interpreter_), executer_, metadata_file,
            storage_path};

        EXPECT_EQ(fs_meta.add(new_file_hash, new_file_name),
            std::filesystem::path {storage_path} / new_file_name);
        expected_storage_map.emplace(new_file_hash, new_file_name);

        for (const auto &[hash, name] : expected_storage_map)
        {
            EXPECT_TRUE(fs_meta.contains(hash));
            EXPECT_EQ(fs_meta.get_file_path(hash), std::filesystem::path {storage_path} / name);
        }
    }

    auto actual_storage_map = get_storage_map(metadata_file);
    EXPECT_EQ(actual_storage_map.size(), number_of_files + 1);
    ASSERT_THAT(actual_storage_map, ContainerEq(expected_storage_map));

    std::filesystem::remove(metadata_file);
    std::filesystem::remove_all(storage_path);
}

TEST_F(FileStorageMetadataTest, AddFile_DuplicateHash)
{
    const std::string storage_path    = "fake_storage";
    const std::string metadata_file   = "storage_metadata.json";
    const int         number_of_files = 10;
    const std::string new_file_name   = "new_file_name";

    auto expected_storage_map = create_storage(storage_path, number_of_files);
    create_metadata_file(expected_storage_map, metadata_file);

    {
        FileStorageMetadataImpl fs_meta {
            std::unique_ptr<FileHashInterpreter>(file_hash_interpreter_), executer_, metadata_file,
            storage_path};

        EXPECT_EQ(fs_meta.add(expected_storage_map.cbegin()->first, new_file_name), "");
    }

    std::filesystem::remove(metadata_file);
    std::filesystem::remove_all(storage_path);
}

TEST_F(FileStorageMetadataTest, AddFile_DuplicateName)
{
    const std::string storage_path    = "fake_storage";
    const std::string metadata_file   = "storage_metadata.json";
    const int         number_of_files = 10;
    const std::string new_file_hash   = "new_file_hash";

    auto expected_storage_map = create_storage(storage_path, number_of_files);
    create_metadata_file(expected_storage_map, metadata_file);

    {
        FileStorageMetadataImpl fs_meta {
            std::unique_ptr<FileHashInterpreter>(file_hash_interpreter_), executer_, metadata_file,
            storage_path};

        EXPECT_EQ(fs_meta.add(new_file_hash, expected_storage_map.cbegin()->second), "");
    }

    std::filesystem::remove(metadata_file);
    std::filesystem::remove_all(storage_path);
}

TEST_F(FileStorageMetadataTest, RemoveFile)
{
    const std::string storage_path    = "fake_storage";
    const std::string metadata_file   = "storage_metadata.json";
    const int         number_of_files = 10;

    auto expected_storage_map = create_storage(storage_path, number_of_files);
    create_metadata_file(expected_storage_map, metadata_file);

    {
        FileStorageMetadataImpl fs_meta {
            std::unique_ptr<FileHashInterpreter>(file_hash_interpreter_), executer_, metadata_file,
            storage_path};

        EXPECT_TRUE(fs_meta.remove(expected_storage_map.cbegin()->first));
        expected_storage_map.erase(expected_storage_map.cbegin());

        for (const auto &[hash, name] : expected_storage_map)
        {
            EXPECT_TRUE(fs_meta.contains(hash));
            EXPECT_EQ(fs_meta.get_file_path(hash), std::filesystem::path {storage_path} / name);
        }
    }

    auto actual_storage_map = get_storage_map(metadata_file);
    EXPECT_EQ(actual_storage_map.size(), number_of_files - 1);
    ASSERT_THAT(actual_storage_map, ContainerEq(expected_storage_map));

    std::filesystem::remove(metadata_file);
    std::filesystem::remove_all(storage_path);
}

TEST_F(FileStorageMetadataTest, RemoveFile_FileNotPresent)
{
    const std::string storage_path    = "fake_storage";
    const std::string metadata_file   = "storage_metadata.json";
    const int         number_of_files = 10;

    auto expected_storage_map = create_storage(storage_path, number_of_files);
    create_metadata_file(expected_storage_map, metadata_file);

    {
        FileStorageMetadataImpl fs_meta {
            std::unique_ptr<FileHashInterpreter>(file_hash_interpreter_), executer_, metadata_file,
            storage_path};

        EXPECT_FALSE(fs_meta.remove("Otelu_galati"));
    }

    std::filesystem::remove(metadata_file);
    std::filesystem::remove_all(storage_path);
}
