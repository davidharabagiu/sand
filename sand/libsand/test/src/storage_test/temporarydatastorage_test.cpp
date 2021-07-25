#include <gtest/gtest.h>

#include <algorithm>

#include "random.hpp"
#include "temporarydatastorageimpl.hpp"

using namespace ::testing;
using namespace ::sand::storage;
using namespace ::sand::utils;

namespace
{
class TemporaryDataStorageTest : public Test
{
protected:
    struct WriteInfo
    {
        std::vector<uint8_t> data;
        size_t               offset = 0;
        size_t               amount = 0;
    };

    Random rng_;
};
}  // namespace

#include <iostream>

TEST_F(TemporaryDataStorageTest, SparseWritesOfSameSize)
{
    const size_t storage_size     = 1024 * 1024;
    const size_t write_size       = 4 * 1024;
    const size_t number_of_writes = 10;

    std::vector<WriteInfo> writes(number_of_writes);
    size_t                 last_write_offset = 0;
    for (auto &w : writes)
    {
        w.amount = write_size;
        w.offset = last_write_offset + write_size + rng_.next<size_t>(50 * 1024);
        w.data.resize(w.amount);
        std::generate(w.data.begin(), w.data.end(), [&] { return rng_.next<uint8_t>(); });
        last_write_offset = w.offset;
    }

    TemporaryDataStorageImpl temp_storage;

    auto handle = temp_storage.create(storage_size);
    EXPECT_NE(handle, TemporaryDataStorage::invalid_handle);

    for (const auto &w : writes)
    {
        EXPECT_TRUE(temp_storage.write(handle, w.offset, w.amount, w.data.data()));
    }

    EXPECT_TRUE(temp_storage.start_reading(handle));

    std::vector<uint8_t> read_data(write_size);
    size_t               read_offset;
    size_t               read_amount;
    for (const auto &w : writes)
    {
        EXPECT_TRUE(temp_storage.read_next_chunk(
            handle, write_size, read_offset, read_amount, read_data.data()));
        EXPECT_EQ(read_offset, w.offset);
        EXPECT_EQ(read_amount, w.amount);
        EXPECT_EQ(read_data, w.data);
    }

    EXPECT_FALSE(temp_storage.read_next_chunk(
        handle, write_size, read_offset, read_amount, read_data.data()));
}

TEST_F(TemporaryDataStorageTest, ContigousWritesOfSameSize_MultipleReads)
{
    const size_t storage_size     = 40 * 1024;
    const size_t write_size       = 4 * 1024;
    const size_t number_of_writes = 10;

    std::vector<WriteInfo> writes(number_of_writes);
    size_t                 next_write_offset = 0;
    for (auto &w : writes)
    {
        w.amount = write_size;
        w.offset = next_write_offset;
        w.data.resize(w.amount);
        std::generate(w.data.begin(), w.data.end(), [&] { return rng_.next<uint8_t>(); });
        next_write_offset = w.offset + w.amount;
    }

    TemporaryDataStorageImpl temp_storage;

    auto handle = temp_storage.create(storage_size);
    EXPECT_NE(handle, TemporaryDataStorage::invalid_handle);

    for (const auto &w : writes)
    {
        EXPECT_TRUE(temp_storage.write(handle, w.offset, w.amount, w.data.data()));
    }

    EXPECT_TRUE(temp_storage.start_reading(handle));

    std::vector<uint8_t> read_data(write_size);
    size_t               read_offset;
    size_t               read_amount;
    for (const auto &w : writes)
    {
        EXPECT_TRUE(temp_storage.read_next_chunk(
            handle, write_size, read_offset, read_amount, read_data.data()));
        EXPECT_EQ(read_offset, w.offset);
        EXPECT_EQ(read_amount, w.amount);
        EXPECT_EQ(read_data, w.data);
    }

    EXPECT_FALSE(temp_storage.read_next_chunk(
        handle, write_size, read_offset, read_amount, read_data.data()));
}

TEST_F(TemporaryDataStorageTest, ContigousWritesOfSameSize_OneBigRead)
{
    const size_t storage_size     = 40 * 1024;
    const size_t write_size       = 4 * 1024;
    const size_t number_of_writes = 10;

    std::vector<WriteInfo> writes(number_of_writes);
    size_t                 next_write_offset = 0;
    for (auto &w : writes)
    {
        w.amount = write_size;
        w.offset = next_write_offset;
        w.data.resize(w.amount);
        std::generate(w.data.begin(), w.data.end(), [&] { return rng_.next<uint8_t>(); });
        next_write_offset = w.offset + w.amount;
    }

    TemporaryDataStorageImpl temp_storage;

    auto handle = temp_storage.create(storage_size);
    EXPECT_NE(handle, TemporaryDataStorage::invalid_handle);

    for (const auto &w : writes)
    {
        EXPECT_TRUE(temp_storage.write(handle, w.offset, w.amount, w.data.data()));
    }

    EXPECT_TRUE(temp_storage.start_reading(handle));

    std::vector<uint8_t> read_data(storage_size);
    size_t               read_offset;
    size_t               read_amount;
    EXPECT_TRUE(temp_storage.read_next_chunk(
        handle, read_data.size(), read_offset, read_amount, read_data.data()));
    EXPECT_EQ(read_offset, 0);
    EXPECT_EQ(read_amount, read_data.size());

    for (const auto &w : writes)
    {
        EXPECT_TRUE(std::equal(w.data.cbegin(), w.data.cend(), read_data.data() + w.offset));
    }

    EXPECT_FALSE(temp_storage.read_next_chunk(
        handle, read_data.size(), read_offset, read_amount, read_data.data()));
}

TEST_F(TemporaryDataStorageTest, OneBigWrite_MultipleReads)
{
    const size_t storage_size  = 33 * 1024;
    const size_t max_read_size = 4 * 1024;

    TemporaryDataStorageImpl temp_storage;

    auto handle = temp_storage.create(storage_size);
    EXPECT_NE(handle, TemporaryDataStorage::invalid_handle);

    std::vector<uint8_t> write_data(storage_size);
    std::generate(write_data.begin(), write_data.end(), [&] { return rng_.next<uint8_t>(); });
    EXPECT_TRUE(temp_storage.write(handle, 0, write_data.size(), write_data.data()));

    EXPECT_TRUE(temp_storage.start_reading(handle));

    std::vector<uint8_t> read_data(max_read_size);
    size_t               read_offset;
    size_t               read_amount;
    size_t               next_read_expected_offset = 0;
    size_t               total_bytes_read          = 0;

    while (temp_storage.read_next_chunk(
        handle, max_read_size, read_offset, read_amount, read_data.data()))
    {
        EXPECT_EQ(read_offset, next_read_expected_offset);
        if (read_offset + max_read_size > storage_size)
        {
            EXPECT_EQ(read_amount, storage_size - read_offset);
        }
        else
        {
            EXPECT_EQ(read_amount, max_read_size);
        }
        EXPECT_TRUE(std::equal(
            read_data.data(), read_data.data() + read_amount, write_data.data() + read_offset));
        next_read_expected_offset = read_offset + read_amount;
        total_bytes_read += read_amount;
    }
    EXPECT_EQ(total_bytes_read, write_data.size());

    EXPECT_FALSE(temp_storage.read_next_chunk(
        handle, max_read_size, read_offset, read_amount, read_data.data()));
}

TEST_F(TemporaryDataStorageTest, SparseWritesOfVariousSizes)
{
    const size_t storage_size     = 1024 * 1024;
    const size_t write_size_min   = 1024;
    const size_t write_size_max   = 4 * 1024;
    const size_t number_of_writes = 10;

    std::vector<WriteInfo> writes(number_of_writes);
    size_t                 last_write_offset = 0;
    size_t                 last_write_size   = 0;
    for (auto &w : writes)
    {
        w.amount = rng_.next<size_t>(write_size_min, write_size_max);
        w.offset = last_write_offset + last_write_size + rng_.next<size_t>(1024, 50 * 1024);
        w.data.resize(w.amount);
        std::generate(w.data.begin(), w.data.end(), [&] { return rng_.next<uint8_t>(); });
        last_write_offset = w.offset;
        last_write_size   = w.amount;
    }

    TemporaryDataStorageImpl temp_storage;

    auto handle = temp_storage.create(storage_size);
    EXPECT_NE(handle, TemporaryDataStorage::invalid_handle);

    for (const auto &w : writes)
    {
        EXPECT_TRUE(temp_storage.write(handle, w.offset, w.amount, w.data.data()));
    }

    EXPECT_TRUE(temp_storage.start_reading(handle));

    std::vector<uint8_t> read_data(write_size_max);
    size_t               read_offset;
    size_t               read_amount;
    for (const auto &w : writes)
    {
        EXPECT_TRUE(temp_storage.read_next_chunk(
            handle, w.amount, read_offset, read_amount, read_data.data()));
        EXPECT_EQ(read_offset, w.offset);
        EXPECT_EQ(read_amount, w.amount);
        EXPECT_TRUE(std::equal(w.data.cbegin(), w.data.cend(), read_data.cbegin()));
    }

    EXPECT_FALSE(temp_storage.read_next_chunk(
        handle, write_size_max, read_offset, read_amount, read_data.data()));
}

TEST_F(TemporaryDataStorageTest, SparseWritesOfVariousSizes_FixedReads)
{
    const size_t storage_size        = 1024 * 1024;
    const size_t write_size_min      = 1024;
    const size_t write_size_max      = 4 * 1024;
    const size_t number_of_writes    = 10;
    const size_t max_read_size       = write_size_max;
    size_t       total_bytes_written = 0;

    std::vector<WriteInfo> writes(number_of_writes);
    size_t                 last_write_offset = 0;
    size_t                 last_write_size   = 0;
    for (auto &w : writes)
    {
        w.amount = rng_.next<size_t>(write_size_min, write_size_max);
        w.offset = last_write_offset + last_write_size + rng_.next<size_t>(1024, 50 * 1024);
        w.data.resize(w.amount);
        std::generate(w.data.begin(), w.data.end(), [&] { return rng_.next<uint8_t>(); });
        last_write_offset = w.offset;
        last_write_size   = w.amount;
        total_bytes_written += w.amount;
    }

    TemporaryDataStorageImpl temp_storage;

    auto handle = temp_storage.create(storage_size);
    EXPECT_NE(handle, TemporaryDataStorage::invalid_handle);

    for (const auto &w : writes)
    {
        EXPECT_TRUE(temp_storage.write(handle, w.offset, w.amount, w.data.data()));
    }

    EXPECT_TRUE(temp_storage.start_reading(handle));

    std::vector<uint8_t> read_data(write_size_max);
    size_t               read_offset;
    size_t               read_amount;
    size_t               total_bytes_read = 0;

    while (temp_storage.read_next_chunk(
        handle, max_read_size, read_offset, read_amount, read_data.data()))
    {
        auto write_it = std::find_if(writes.begin(), writes.end(), [&](const WriteInfo &w) {
            return read_offset >= w.offset && read_offset + read_amount <= w.offset + w.amount;
        });
        EXPECT_NE(write_it, writes.end());
        EXPECT_TRUE(std::equal(read_data.data(), read_data.data() + read_amount,
            write_it->data.data() + read_offset - write_it->offset));
        total_bytes_read += read_amount;

        // Zero-fill written data to ensure no overlapped reads occured
        std::fill_n(write_it->data.data() + read_offset - write_it->offset, read_amount, 0);
    }
    EXPECT_EQ(total_bytes_read, total_bytes_written);

    EXPECT_FALSE(temp_storage.read_next_chunk(
        handle, write_size_max, read_offset, read_amount, read_data.data()));
}

TEST_F(TemporaryDataStorageTest, OverlappedWrites)
{
    const size_t storage_size     = 40 * 1024;
    const size_t write_size       = 4 * 1024;
    const size_t number_of_writes = 10;
    const size_t overlap_size     = 1024;

    std::vector<WriteInfo> writes(number_of_writes);
    size_t                 next_write_offset = 0;
    std::vector<uint8_t>   expected_file_content(
        (write_size - overlap_size) * (number_of_writes - 1) + write_size);
    for (auto &w : writes)
    {
        w.amount = write_size;
        w.offset = next_write_offset;
        w.data.resize(w.amount);
        std::generate(w.data.begin(), w.data.end(), [&] { return rng_.next<uint8_t>(); });
        next_write_offset = w.offset + w.amount - overlap_size;
        std::copy(w.data.cbegin(), w.data.cend(), expected_file_content.data() + w.offset);
    }

    TemporaryDataStorageImpl temp_storage;

    auto handle = temp_storage.create(storage_size);
    EXPECT_NE(handle, TemporaryDataStorage::invalid_handle);

    for (const auto &w : writes)
    {
        EXPECT_TRUE(temp_storage.write(handle, w.offset, w.amount, w.data.data()));
    }

    EXPECT_TRUE(temp_storage.start_reading(handle));

    std::vector<uint8_t> read_data(expected_file_content.size());
    size_t               read_offset;
    size_t               read_amount;
    EXPECT_TRUE(temp_storage.read_next_chunk(
        handle, read_data.size(), read_offset, read_amount, read_data.data()));
    EXPECT_EQ(read_offset, 0);
    EXPECT_EQ(read_amount, read_data.size());
    EXPECT_EQ(read_data, expected_file_content);

    EXPECT_FALSE(temp_storage.read_next_chunk(
        handle, read_data.size(), read_offset, read_amount, read_data.data()));
}

TEST_F(TemporaryDataStorageTest, CancelReading)
{
    const size_t storage_size = 1024;

    TemporaryDataStorageImpl temp_storage;

    auto handle = temp_storage.create(storage_size);
    EXPECT_NE(handle, TemporaryDataStorage::invalid_handle);

    std::vector<uint8_t> write_data(storage_size);
    std::generate(write_data.begin(), write_data.end(), [&] { return rng_.next<uint8_t>(); });
    EXPECT_TRUE(temp_storage.write(handle, 0, write_data.size(), write_data.data()));

    EXPECT_TRUE(temp_storage.start_reading(handle));

    std::vector<uint8_t> read_data(storage_size / 2);
    size_t               read_offset;
    size_t               read_amount;
    EXPECT_TRUE(temp_storage.read_next_chunk(
        handle, read_data.size(), read_offset, read_amount, read_data.data()));

    EXPECT_TRUE(temp_storage.cancel_reading(handle));
    EXPECT_FALSE(temp_storage.read_next_chunk(
        handle, read_data.size(), read_offset, read_amount, read_data.data()));

    EXPECT_TRUE(temp_storage.write(handle, 0, write_data.size(), write_data.data()));
}

TEST_F(TemporaryDataStorageTest, ReadingNotStarted)
{
    const size_t storage_size = 1024;

    TemporaryDataStorageImpl temp_storage;

    auto handle = temp_storage.create(storage_size);
    EXPECT_NE(handle, TemporaryDataStorage::invalid_handle);

    std::vector<uint8_t> write_data(storage_size);
    std::generate(write_data.begin(), write_data.end(), [&] { return rng_.next<uint8_t>(); });
    EXPECT_TRUE(temp_storage.write(handle, 0, write_data.size(), write_data.data()));

    std::vector<uint8_t> read_data(storage_size);
    size_t               read_offset;
    size_t               read_amount;
    EXPECT_FALSE(temp_storage.read_next_chunk(
        handle, read_data.size(), read_offset, read_amount, read_data.data()));
}

TEST_F(TemporaryDataStorageTest, RemoveStorage)
{
    const size_t storage_size = 1024;

    TemporaryDataStorageImpl temp_storage;

    auto handle = temp_storage.create(storage_size);
    EXPECT_NE(handle, TemporaryDataStorage::invalid_handle);

    std::vector<uint8_t> write_data(storage_size);
    std::generate(write_data.begin(), write_data.end(), [&] { return rng_.next<uint8_t>(); });
    EXPECT_TRUE(temp_storage.write(handle, 0, write_data.size(), write_data.data()));

    temp_storage.remove(handle);
    EXPECT_FALSE(temp_storage.write(handle, 0, write_data.size(), write_data.data()));
}

TEST_F(TemporaryDataStorageTest, WritingInReadingState)
{
    const size_t storage_size = 1024;

    TemporaryDataStorageImpl temp_storage;

    auto handle = temp_storage.create(storage_size);
    EXPECT_NE(handle, TemporaryDataStorage::invalid_handle);

    std::vector<uint8_t> write_data(storage_size);
    std::generate(write_data.begin(), write_data.end(), [&] { return rng_.next<uint8_t>(); });
    EXPECT_TRUE(temp_storage.write(handle, 0, write_data.size(), write_data.data()));

    EXPECT_TRUE(temp_storage.start_reading(handle));
    EXPECT_FALSE(temp_storage.write(handle, 0, write_data.size(), write_data.data()));
}

TEST_F(TemporaryDataStorageTest, StartReadingSecondTimeFails)
{
    const size_t storage_size = 1024;

    TemporaryDataStorageImpl temp_storage;

    auto handle = temp_storage.create(storage_size);
    EXPECT_NE(handle, TemporaryDataStorage::invalid_handle);

    std::vector<uint8_t> write_data(storage_size);
    std::generate(write_data.begin(), write_data.end(), [&] { return rng_.next<uint8_t>(); });
    EXPECT_TRUE(temp_storage.write(handle, 0, write_data.size(), write_data.data()));

    EXPECT_TRUE(temp_storage.start_reading(handle));
    EXPECT_FALSE(temp_storage.start_reading(handle));
}

TEST_F(TemporaryDataStorageTest, CompletingReadSetsStateToWriting)
{
    const size_t storage_size = 1024;

    TemporaryDataStorageImpl temp_storage;

    auto handle = temp_storage.create(storage_size);
    EXPECT_NE(handle, TemporaryDataStorage::invalid_handle);

    std::vector<uint8_t> write_data(storage_size);
    std::generate(write_data.begin(), write_data.end(), [&] { return rng_.next<uint8_t>(); });
    EXPECT_TRUE(temp_storage.write(handle, 0, write_data.size(), write_data.data()));

    EXPECT_TRUE(temp_storage.start_reading(handle));

    std::vector<uint8_t> read_data(storage_size);
    size_t               read_offset;
    size_t               read_amount;
    EXPECT_TRUE(temp_storage.read_next_chunk(
        handle, read_data.size(), read_offset, read_amount, read_data.data()));

    EXPECT_FALSE(temp_storage.read_next_chunk(
        handle, read_data.size(), read_offset, read_amount, read_data.data()));
    EXPECT_TRUE(temp_storage.write(handle, 0, write_data.size(), write_data.data()));
}

TEST_F(TemporaryDataStorageTest, InvalidHandle)
{
    const size_t storage_size = 1024;

    TemporaryDataStorageImpl temp_storage;

    std::vector<uint8_t> write_data(storage_size);
    std::generate(write_data.begin(), write_data.end(), [&] { return rng_.next<uint8_t>(); });
    EXPECT_FALSE(temp_storage.write(666, 0, write_data.size(), write_data.data()));
}

TEST_F(TemporaryDataStorageTest, OutOfBoundsWrite)
{
    const size_t storage_size = 1024;

    TemporaryDataStorageImpl temp_storage;

    auto handle = temp_storage.create(storage_size);
    EXPECT_NE(handle, TemporaryDataStorage::invalid_handle);

    std::vector<uint8_t> write_data(storage_size + 1);
    std::generate(write_data.begin(), write_data.end(), [&] { return rng_.next<uint8_t>(); });
    EXPECT_FALSE(temp_storage.write(handle, 0, write_data.size(), write_data.data()));
}
