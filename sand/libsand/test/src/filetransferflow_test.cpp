#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <memory>

#include "filetransferflowimpl.hpp"
#include "inboundrequestdispatcher.hpp"
#include "random.hpp"
#include "threadpool.hpp"

#include "aescipher_mock.hpp"
#include "filehashinterpreter_mock.hpp"
#include "filestorage_mock.hpp"
#include "filetransferflowlistener_mock.hpp"
#include "peeraddressprovider_mock.hpp"
#include "protocolmessagehandler_mock.hpp"
#include "temporarydatastorage_mock.hpp"

using namespace ::testing;
using namespace ::sand::flows;

namespace
{
class FileTransferFLowTest : public Test
{
protected:
    void SetUp() override
    {
        protocol_message_handler_ = std::make_shared<NiceMock<ProtocolMessageHandlerMock>>();
        inbound_request_dispatcher_ =
            std::make_shared<InboundRequestDispatcher>(protocol_message_handler_);
        peer_address_provider_  = std::make_shared<NiceMock<PeerAddressProviderMock>>();
        file_storage_           = std::make_shared<NiceMock<FileStorageMock>>();
        file_hash_interpreter_  = new NiceMock<FileHashInterpreterMock>();
        temporary_data_storage_ = std::make_shared<NiceMock<TemporaryDataStorageMock>>();
        aes_                    = std::make_shared<NiceMock<AESCipherMock>>();
        thread_pool_            = std::make_shared<ThreadPool>();
        listener_               = std::make_shared<NiceMock<FileTransferFlowListenerMock>>();
    }

    std::unique_ptr<FileTransferFlow> make_flow(int receive_file_timeout = 0,
        int drop_point_request_timeout = 0, int lift_proxy_request_timeout = 0,
        int drop_point_transfer_timeout = 0, int lift_proxy_transfer_timeout = 0)
    {
        return std::make_unique<FileTransferFlowImpl>(protocol_message_handler_,
            inbound_request_dispatcher_, peer_address_provider_, file_storage_,
            std::unique_ptr<FileHashInterpreter>(file_hash_interpreter_), temporary_data_storage_,
            aes_, thread_pool_, thread_pool_, max_part_size_, max_chunk_size_,
            max_temp_storage_size_, receive_file_timeout, drop_point_request_timeout,
            lift_proxy_request_timeout, drop_point_transfer_timeout, lift_proxy_transfer_timeout);
    }

    std::shared_ptr<ProtocolMessageHandlerMock>   protocol_message_handler_;
    std::shared_ptr<InboundRequestDispatcher>     inbound_request_dispatcher_;
    std::shared_ptr<PeerAddressProviderMock>      peer_address_provider_;
    std::shared_ptr<FileStorageMock>              file_storage_;
    FileHashInterpreterMock *                     file_hash_interpreter_;
    std::shared_ptr<TemporaryDataStorageMock>     temporary_data_storage_;
    std::shared_ptr<AESCipherMock>                aes_;
    std::shared_ptr<Executer>                     thread_pool_;
    std::shared_ptr<FileTransferFlowListenerMock> listener_;
    Random                                        rng_;
    const size_t                                  max_part_size_         = 1024;  // 1KiB
    const size_t                                  max_chunk_size_        = 128;
    const size_t                                  max_temp_storage_size_ = 4096;  // 4KiB
};
}  // namespace
