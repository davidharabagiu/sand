#ifndef SAND_TEST_FILEHASHCALCULATOR_MOCK_HPP_
#define SAND_TEST_FILEHASHCALCULATOR_MOCK_HPP_

#include <gmock/gmock.h>

#include "filehashcalculator.hpp"

using namespace ::sand::storage;

class FileHashCalculatorMock : public FileHashCalculator
{
public:
    MOCK_METHOD(bool, decode, (const std::string &, uint8_t *), (override));
    MOCK_METHOD(std::string, encode, (const uint8_t *), (override));
};

#endif  // SAND_TEST_FILEHASHCALCULATOR_MOCK_HPP_
