#ifndef SAND_TEST_FILELOCATORFLOWLISTENER_MOCK_HPP_
#define SAND_TEST_FILELOCATORFLOWLISTENER_MOCK_HPP_

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using namespace sand::flows;

class FileLocatorFlowListenerMock : public FileLocatorFlowListener
{
public:
    MOCK_METHOD(void, on_state_changed, (FileLocatorFlow::State), (override));
    MOCK_METHOD(void, on_file_found, (const TransferHandle &), (override));
    MOCK_METHOD(void, on_file_wanted, (const SearchHandle &), (override));
    MOCK_METHOD(void, on_transfer_confirmed, (const TransferHandle &), (override));
};

#endif  // SAND_TEST_FILELOCATORFLOWLISTENER_MOCK_HPP_
