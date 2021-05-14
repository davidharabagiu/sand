#ifndef SAND_TEST_EXECUTER_MOCK_HPP_
#define SAND_TEST_EXECUTER_MOCK_HPP_

#include <gmock/gmock.h>

#include "executer.hpp"

using namespace ::sand::utils;

class ExecuterMock : public Executer
{
public:
    MOCK_METHOD(void, add_job, (Job &&, Priority), (override));
};

#endif  // SAND_TEST_EXECUTER_MOCK_HPP_
