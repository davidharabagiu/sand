#ifndef SAND_TEST_TEMPORARYDATASTORAGE_MOCK_HPP_
#define SAND_TEST_TEMPORARYDATASTORAGE_MOCK_HPP_

#include <gmock/gmock.h>

#include "temporarydatastorage.hpp"

using namespace ::sand::storage;

class TemporaryDataStorageMock : public TemporaryDataStorage
{
public:
    MOCK_METHOD(Handle, create, (size_t), (override));
    MOCK_METHOD(bool, start_reading, (Handle), (override));
    MOCK_METHOD(bool, read_next_chunk, (Handle, size_t, size_t &, size_t &, uint8_t *), (override));
    MOCK_METHOD(bool, cancel_reading, (Handle), (override));
    MOCK_METHOD(bool, write, (Handle, size_t, size_t, const uint8_t *), (override));
    MOCK_METHOD(void, remove, (Handle), (override));
};

#endif  // SAND_TEST_TEMPORARYDATASTORAGE_MOCK_HPP_
