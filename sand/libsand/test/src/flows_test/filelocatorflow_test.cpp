#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <memory>

#include "filelocatorflowimpl.hpp"
#include "inboundrequestdispatcher.hpp"
#include "iothreadpool.hpp"
#include "threadpool.hpp"

#include "filehashcalculator_mock.hpp"
#include "filelocatorflowlistener_mock.hpp"
#include "filestorage_mock.hpp"
#include "peeraddressprovider_mock.hpp"
#include "protocolmessagehandler_mock.hpp"
#include "secretdatainterpreter_mock.hpp"

using namespace ::sand::flows;
using namespace ::sand::utils;
using namespace ::sand::protocol;
using namespace ::sand::storage;
using namespace ::testing;

namespace
{
class FileLocatorFlowTest : public Test
{
protected:
    void SetUp() override
    {
        protocol_message_handler_ = std::make_shared<NiceMock<ProtocolMessageHandlerMock>>();
        inbound_request_dispatcher_ =
            std::make_shared<InboundRequestDispatcher>(protocol_message_handler_);
        peer_address_provider_   = std::make_shared<NiceMock<PeerAddressProviderMock>>();
        file_storage_            = std::make_shared<NiceMock<FileStorageMock>>();
        file_hash_calculator_    = new NiceMock<FileHashCalculatorMock>();
        secret_data_interpreter_ = std::make_shared<NiceMock<SecretDataInterpreterMock>>();
        thread_pool_             = std::make_shared<ThreadPool>();
        io_thread_pool_          = std::make_shared<IOThreadPool>();
        listener_                = std::make_shared<NiceMock<FileLocatorFlowListenerMock>>();
    }

    std::unique_ptr<FileLocatorFlow> make_flow(
        int search_timeout_sec = 0, int routing_table_entry_expiration_time_sec = 0)
    {
        return std::make_unique<FileLocatorFlowImpl>(protocol_message_handler_,
            inbound_request_dispatcher_, peer_address_provider_, file_storage_,
            std::unique_ptr<FileHashCalculator>(file_hash_calculator_), secret_data_interpreter_,
            thread_pool_, io_thread_pool_, pub_key_, pri_key_, search_propagation_degree_,
            search_timeout_sec, routing_table_entry_expiration_time_sec);
    }

    std::shared_ptr<ProtocolMessageHandlerMock>  protocol_message_handler_;
    std::shared_ptr<InboundRequestDispatcher>    inbound_request_dispatcher_;
    std::shared_ptr<PeerAddressProviderMock>     peer_address_provider_;
    std::shared_ptr<FileStorageMock>             file_storage_;
    FileHashCalculatorMock *                     file_hash_calculator_;
    std::shared_ptr<SecretDataInterpreterMock>   secret_data_interpreter_;
    std::shared_ptr<Executer>                    thread_pool_;
    std::shared_ptr<Executer>                    io_thread_pool_;
    std::shared_ptr<FileLocatorFlowListenerMock> listener_;
    const std::string                            pub_key_                   = "pub_key";
    const std::string                            pri_key_                   = "pri_key";
    const int                                    search_propagation_degree_ = 5;
};
}  // namespace

TEST_F(FileLocatorFlowTest, StartStop_StateChanges)
{
    auto flow = make_flow();
    EXPECT_EQ(flow->state(), FileLocatorFlow::State::IDLE);

    flow->start();
    EXPECT_EQ(flow->state(), FileLocatorFlow::State::RUNNING);

    flow->stop();
    EXPECT_EQ(flow->state(), FileLocatorFlow::State::IDLE);
}

TEST_F(FileLocatorFlowTest, StartStop_StateChangesAreNotified)
{
    auto flow = make_flow();
    flow->register_listener(listener_);

    EXPECT_CALL(*listener_, on_state_changed(FileLocatorFlow::State::RUNNING)).Times(1);
    flow->start();
    Mock::VerifyAndClearExpectations(listener_.get());

    EXPECT_CALL(*listener_, on_state_changed(FileLocatorFlow::State::STOPPING)).Times(1);
    EXPECT_CALL(*listener_, on_state_changed(FileLocatorFlow::State::IDLE)).Times(1);
}
