#ifndef SAND_TEST_FILETRANSFERFLOWLISTENER_MOCK_HPP_
#define SAND_TEST_FILETRANSFERFLOWLISTENER_MOCK_HPP_

#include <gmock/gmock.h>

#include "filetransferflowlistener.hpp"

using namespace ::sand::flows;

class FileTransferFlowListenerMock : public FileTransferFlowListener
{
public:
    MOCK_METHOD(void, on_state_changed, (FileTransferFlow::State), (override));
    MOCK_METHOD(
        void, on_transfer_progress_changed, (const TransferHandle &, size_t, size_t), (override));
    MOCK_METHOD(void, on_transfer_completed, (const TransferHandle &), (override));
    MOCK_METHOD(void, on_transfer_error, (const TransferHandle &, const std::string &), (override));
};

#endif  // SAND_TEST_FILETRANSFERFLOWLISTENER_MOCK_HPP_
