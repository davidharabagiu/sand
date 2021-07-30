#include "sandnodeimpl.hpp"

#include <chrono>
#include <filesystem>
#include <sstream>
#include <utility>

#include <glog/logging.h>

#include "aescipherimpl.hpp"
#include "base64encoderimpl.hpp"
#include "defaultconfigvalues.hpp"
#include "dnlconfig.hpp"
#include "filehashinterpreterimpl.hpp"
#include "filelocatorflowimpl.hpp"
#include "filelocatorflowlistenerdelegate.hpp"
#include "filestorageimpl.hpp"
#include "filestoragemetadataimpl.hpp"
#include "filetransferflowimpl.hpp"
#include "filetransferflowlistenerdelegate.hpp"
#include "inboundrequestdispatcher.hpp"
#include "iothreadpool.hpp"
#include "jsonconfigloader.hpp"
#include "mainexecuter.hpp"
#include "messageserializerimpl.hpp"
#include "peermanagerflowimpl.hpp"
#include "peermanagerflowlistenerdelegate.hpp"
#include "protocolmessagehandlerimpl.hpp"
#include "rsacipherimpl.hpp"
#include "secretdatainterpreterimpl.hpp"
#include "sha3hasherimpl.hpp"
#include "tcpsenderimpl.hpp"
#include "tcpserverimpl.hpp"
#include "temporarydatastorageimpl.hpp"
#include "textfilednlconfigloader.hpp"
#include "threadpool.hpp"
#include "timer.hpp"

namespace
{
std::string path_join(const std::string &directory, const std::string &file_name)
{
    return (std::filesystem::path {directory} / file_name).string();
}

std::unique_ptr<sand::storage::FileHashInterpreter> make_file_hash_interpreter()
{
    return std::make_unique<sand::storage::FileHashInterpreterImpl>(
        std::make_unique<sand::crypto::Base64EncoderImpl>(),
        std::make_unique<sand::crypto::SHA3HasherImpl>());
}
}  // namespace

namespace sand
{
SANDNodeImpl::SANDNodeImpl(std::string app_data_dir_path, const std::string &config_file_name)
    : state_ {State::IDLE}
    , upload_state_ {UploadState::IDLE}
    , latest_download_succeeded_ {false}
    , app_data_dir_path_ {std::move(app_data_dir_path)}
    , cfg_ {config::JSONConfigLoader {path_join(app_data_dir_path_, config_file_name)},
          std::make_unique<DefaultConfigValues>()}
    , peer_manager_flow_listener_ {std::make_shared<PeerManagerFlowListenerDelegate>()}
    , file_locator_flow_listener_ {std::make_shared<FileLocatorFlowListenerDelegate>()}
    , file_transfer_flow_listener_ {std::make_shared<FileTransferFlowListenerDelegate>()}
{
    peer_manager_flow_listener_->set_on_state_changed_cb(
        [this](auto &&a1) { on_peer_manager_flow_state_changed(std::forward<decltype(a1)>(a1)); });
    file_locator_flow_listener_->set_on_state_changed_cb(
        [this](auto &&a1) { on_file_locator_flow_state_changed(std::forward<decltype(a1)>(a1)); });
    file_locator_flow_listener_->set_on_file_found_cb(
        [this](auto &&a1) { on_file_found(std::forward<decltype(a1)>(a1)); });
    file_locator_flow_listener_->set_on_file_wanted_cb(
        [this](auto &&a1) { on_file_wanted(std::forward<decltype(a1)>(a1)); });
    file_locator_flow_listener_->set_on_transfer_confirmed_cb(
        [this](auto &&a1) { on_transfer_confirmed(std::forward<decltype(a1)>(a1)); });
    file_transfer_flow_listener_->set_on_state_changed_cb(
        [this](auto &&a1) { on_file_transfer_flow_state_changed(std::forward<decltype(a1)>(a1)); });
    file_transfer_flow_listener_->set_on_transfer_progress_changed_cb(
        [this](auto &&a1, auto &&a2, auto &&a3) {
            on_transfer_progress_changed(std::forward<decltype(a1)>(a1),
                std::forward<decltype(a2)>(a2), std::forward<decltype(a3)>(a3));
        });
    file_transfer_flow_listener_->set_on_transfer_completed_cb(
        [this](auto &&a1) { on_transfer_completed(std::forward<decltype(a1)>(a1)); });
    file_transfer_flow_listener_->set_on_transfer_error_cb([this](auto &&a1, auto &&a2) {
        on_transfer_error(std::forward<decltype(a1)>(a1), std::forward<decltype(a2)>(a2));
    });
}

SANDNodeImpl::~SANDNodeImpl()
{
    if (state() == State::RUNNING)
    {
        stop();
    }
}

bool SANDNodeImpl::register_listener(const std::shared_ptr<SANDNodeListener> &listener)
{
    return listener_group_.add(listener);
}

bool SANDNodeImpl::unregister_listener(const std::shared_ptr<SANDNodeListener> &listener)
{
    return listener_group_.remove(listener);
}

bool SANDNodeImpl::start()
{
    auto current_state = state();
    if (current_state != State::IDLE)
    {
        LOG(WARNING) << "Cannot start node from state " << to_string(current_state);
        return false;
    }
    set_state(State::STARTING);

    auto storage_dir =
        path_join(app_data_dir_path_, cfg_.get_string(config::ConfigKey::FILE_STORAGE_DIR));
    if (!std::filesystem::exists(storage_dir))
    {
        std::error_code ec;
        std::filesystem::create_directories(storage_dir, ec);
        if (ec)
        {
            LOG(ERROR) << "Cannot create application data directory: " << ec.message();
            set_state(State::IDLE);
            return false;
        }
    }

    std::string public_key;
    std::string private_key;

    thread_pool_ = std::make_shared<utils::ThreadPool>();

    auto rsa = std::make_shared<crypto::RSACipherImpl>();
    if (!rsa->generate_key_pair(crypto::RSACipher::M2048, crypto::RSACipher::E65537, public_key,
                private_key, *thread_pool_)
             .get())
    {
        LOG(ERROR) << "Cannot generate RSA key pair";
        rsa.reset();
        set_state(State::IDLE);
        return false;
    }

    io_thread_pool_    = std::make_shared<utils::IOThreadPool>();
    tcp_sender_io_ctx_ = std::make_unique<boost::asio::io_context>();
    tcp_server_io_ctx_ = std::make_unique<boost::asio::io_context>();

    pending_transfer_confirmation_timeout_ = std::make_unique<utils::Timer>(io_thread_pool_);

    io_thread_pool_->add_job([this](const utils::CompletionToken &) { tcp_sender_io_ctx_->run(); });
    io_thread_pool_->add_job([this](const utils::CompletionToken &) { tcp_server_io_ctx_->run(); });

    auto tcp_sender               = std::make_shared<network::TCPSenderImpl>(*tcp_sender_io_ctx_);
    auto tcp_server               = std::make_shared<network::TCPServerImpl>(*tcp_server_io_ctx_,
        static_cast<unsigned short>(cfg_.get_integer(config::ConfigKey::PORT)));
    auto message_serializer       = std::make_shared<protocol::MessageSerializerImpl>();
    auto protocol_message_handler = std::make_shared<protocol::ProtocolMessageHandlerImpl>(
        tcp_sender, tcp_server, message_serializer, io_thread_pool_, cfg_);
    auto inbound_request_dispatcher =
        std::make_shared<flows::InboundRequestDispatcher>(protocol_message_handler);
    auto dnl_config = std::make_shared<config::DNLConfig>(
        std::make_unique<config::TextFileDNLConfigLoader>(path_join(
            app_data_dir_path_, cfg_.get_string(config::ConfigKey::KNOWN_DNL_NODES_LIST_FILE))));
    auto storage_metadata = std::make_shared<storage::FileStorageMetadataImpl>(
        make_file_hash_interpreter(), thread_pool_,
        path_join(app_data_dir_path_, cfg_.get_string(config::ConfigKey::METADATA_FILE)),
        storage_dir);
    auto temporary_data_storage = std::make_shared<storage::TemporaryDataStorageImpl>();
    auto secret_data_interpreter =
        std::make_shared<protocol::SecretDataInterpreterImpl>(rsa, thread_pool_);
    auto aes = std::make_shared<crypto::AESCipherImpl>();

    file_storage_ = std::make_shared<storage::FileStorageImpl>(storage_metadata);

    peer_manager_flow_  = std::make_shared<flows::PeerManagerFlowImpl>(protocol_message_handler,
        inbound_request_dispatcher, dnl_config, thread_pool_, io_thread_pool_, cfg_);
    file_locator_flow_  = std::make_unique<flows::FileLocatorFlowImpl>(protocol_message_handler,
        inbound_request_dispatcher, peer_manager_flow_, file_storage_, make_file_hash_interpreter(),
        secret_data_interpreter, thread_pool_, io_thread_pool_, public_key, private_key, cfg_);
    file_transfer_flow_ = std::make_unique<flows::FileTransferFlowImpl>(protocol_message_handler,
        inbound_request_dispatcher, peer_manager_flow_, file_storage_, make_file_hash_interpreter(),
        temporary_data_storage, aes, thread_pool_, io_thread_pool_, cfg_);

    protocol_message_handler->initialize();
    inbound_request_dispatcher->initialize();
    peer_manager_flow_listener_->register_as_listener(*peer_manager_flow_);
    file_locator_flow_listener_->register_as_listener(*file_locator_flow_);
    file_transfer_flow_listener_->register_as_listener(*file_transfer_flow_);

    peer_manager_flow_->start();
    file_locator_flow_->start();
    file_transfer_flow_->start();

    {
        std::unique_lock lock {mutex_};
        cv_waiting_for_start_.wait(lock, [this] {
            return ((peer_manager_flow_->state() == flows::PeerManagerFlow::State::ERROR ||
                        peer_manager_flow_->state() == flows::PeerManagerFlow::State::RUNNING) &&
                       file_locator_flow_->state() == flows::FileLocatorFlow::State::RUNNING &&
                       file_transfer_flow_->state() == flows::FileTransferFlow::State::RUNNING) ||
                   state_ == State::IDLE;
        });

        if (state_ == State::IDLE)
        {
            return false;
        }
    }

    if (peer_manager_flow_->state() == flows::PeerManagerFlow::State::ERROR)
    {
        set_state(State::ERROR);
        stop();
        return false;
    }

    set_state(State::RUNNING);
    return true;
}

bool SANDNodeImpl::stop()
{
    auto current_state = state();
    if (current_state != State::RUNNING && current_state != State::ERROR &&
        current_state != State::SEARCHING && current_state != State::DOWNLOADING)
    {
        LOG(WARNING) << "Cannot stop node from state " << to_string(current_state);
        return false;
    }

    set_state(State::STOPPING);

    tcp_server_io_ctx_->stop();
    tcp_sender_io_ctx_->stop();

    file_locator_flow_->stop();
    file_locator_flow_listener_->unregister_as_listener(*file_locator_flow_);
    file_locator_flow_.reset();

    file_transfer_flow_->stop();
    file_transfer_flow_listener_->unregister_as_listener(*file_transfer_flow_);
    file_transfer_flow_.reset();

    peer_manager_flow_->stop();
    peer_manager_flow_listener_->unregister_as_listener(*peer_manager_flow_);
    peer_manager_flow_.reset();

    file_storage_.reset();
    pending_transfer_confirmation_timeout_.reset();
    thread_pool_.reset();
    io_thread_pool_.reset();
    tcp_server_io_ctx_.reset();
    tcp_sender_io_ctx_.reset();

    upload_state_ = UploadState::IDLE;
    current_download_.clear();
    latest_download_succeeded_ = false;
    latest_download_error_.clear();
    current_upload_.clear();

    set_state(State::IDLE);

    cv_waiting_for_start_.notify_one();
    cv_waiting_for_download_completion_.notify_one();
    cv_waiting_for_search_.notify_one();

    return true;
}

bool SANDNodeImpl::download_file(
    const std::string &file_hash, const std::string &file_name, std::string &error_string)
{
    auto current_state = state();
    if (current_state != State::RUNNING)
    {
        std::ostringstream ss;
        ss << "Cannot start file download from state " << to_string(current_state);
        error_string = ss.str();
        return false;
    }

    if (file_storage_->contains(file_hash))
    {
        error_string = "File already in storage";
        return false;
    }

    auto search_handle = file_locator_flow_->search(file_hash);
    if (!search_handle)
    {
        error_string = "Cannot perform a search for this file, check the logs for more details "
                       "about this problem";
        return false;
    }

    set_state(State::SEARCHING);

    {
        auto pred = [this] { return current_download_.is_valid() || state_ == State::IDLE; };
        std::unique_lock lock {mutex_};
        auto             timeout = cfg_.get_integer(config::ConfigKey::SEARCH_TIMEOUT);
        if (timeout > 0)
        {
            cv_waiting_for_search_.wait_for(lock, std::chrono::seconds {timeout}, pred);
        }
        else
        {
            LOG(WARNING) << "Search timeout disabled, there is a very high risk of endless wait. "
                            "Please set a search timeout in the configuration file.";
            cv_waiting_for_search_.wait(lock, pred);
        }

        if (state_ == State::IDLE)
        {
            return false;
        }

        if (!current_download_)
        {
            error_string =
                "Timeout exceeded and the file was not found - you can try your luck again later";
            return false;
        }

        if (!file_transfer_flow_->receive_file(current_download_, file_name))
        {
            error_string = "Cannot start downloading this file, check the logs for more details "
                           "about this problem";
            return false;
        }
    }

    listener_group_.notify(&SANDNodeListener::on_file_found);
    set_state(State::DOWNLOADING);

    {
        std::unique_lock lock {mutex_};
        cv_waiting_for_download_completion_.wait(
            lock, [this] { return !current_download_ || state_ == State::IDLE; });

        if (state_ == State::IDLE)
        {
            return false;
        }

        if (!latest_download_succeeded_)
        {
            error_string = std::move(latest_download_error_);
            return false;
        }
        latest_download_succeeded_ = false;
    }

    set_state(State::RUNNING);

    return true;
}

SANDNodeImpl::State SANDNodeImpl::state() const
{
    std::lock_guard lock {mutex_};
    return state_;
}

void SANDNodeImpl::set_state(State new_state)
{
    std::lock_guard lock {mutex_};
    state_ = new_state;
}

void SANDNodeImpl::on_peer_manager_flow_state_changed(flows::PeerManagerFlow::State new_state)
{
    if (state() == State::STARTING && (new_state == flows::PeerManagerFlow::State::RUNNING ||
                                          new_state == flows::PeerManagerFlow::State::ERROR))
    {
        cv_waiting_for_start_.notify_one();
    }
}

void SANDNodeImpl::on_file_locator_flow_state_changed(flows::FileLocatorFlow::State new_state)
{
    if (state() == State::STARTING && new_state == flows::FileLocatorFlow::State::RUNNING)
    {
        cv_waiting_for_start_.notify_one();
    }
}

void SANDNodeImpl::on_file_found(const flows::TransferHandle &transfer_handle)
{
    {
        std::lock_guard lock {mutex_};
        if (state_ != State::SEARCHING)
        {
            LOG(ERROR) << "Stray on_file_found callback, wrong state: " << to_string(state_);
            return;
        }
        current_download_ = transfer_handle;
    }
    cv_waiting_for_search_.notify_one();
}

void SANDNodeImpl::on_file_wanted(const flows::SearchHandle &search_handle)
{
    auto current_state = state();
    if (current_state == State::IDLE || current_state == State::STARTING ||
        current_state == State::STOPPING)
    {
        LOG(INFO) << "Current node state not fit for uploading files: " << to_string(current_state);
        return;
    }

    std::lock_guard lock {upload_procedure_mutex_};

    if (upload_state_ != UploadState::IDLE)
    {
        LOG(INFO) << "Upload already in progress or pending upload, ignoring request";
        return;
    }

    auto transfer_handle = file_transfer_flow_->create_offer(search_handle).get();
    if (!file_locator_flow_->send_offer(transfer_handle))
    {
        LOG(ERROR) << "Cannot send offer, abandoning upload procedure";
        return;
    }

    current_upload_ = transfer_handle;
    upload_state_   = UploadState::WAITING_FOR_CONFIRMATION;

    auto confirmation_timeout_sec = cfg_.get_integer(config::ConfigKey::CONFIRM_TRANSFER_TIMEOUT);
    if (confirmation_timeout_sec > 0)
    {
        pending_transfer_confirmation_timeout_->start(
            std::chrono::seconds(confirmation_timeout_sec),
            [this] {
                std::lock_guard lock {upload_procedure_mutex_};
                if (upload_state_ == UploadState::WAITING_FOR_CONFIRMATION)
                {
                    upload_state_ = UploadState::IDLE;
                    current_upload_.clear();
                }
            },
            true);
    }
    else
    {
        LOG(WARNING)
            << "Transfer confirmation timeout disabled, there is a very high risk of endless wait. "
               "Please set a transfer confirmation timeout in the configuration file.";
    }
}

void SANDNodeImpl::on_transfer_confirmed(const flows::TransferHandle &transfer_handle)
{
    auto current_state = state();
    if (current_state == State::IDLE || current_state == State::STARTING ||
        current_state == State::STOPPING)
    {
        LOG(INFO) << "Current node state not fit for uploading files: " << to_string(current_state);
        return;
    }

    std::lock_guard lock {upload_procedure_mutex_};

    if (upload_state_ != UploadState::WAITING_FOR_CONFIRMATION)
    {
        LOG(ERROR) << "Stray on_transfer_confirmed call, wrong upload state: "
                   << to_string(upload_state_);
        return;
    }
    if (current_upload_ != transfer_handle)
    {
        LOG(ERROR) << "Stray on_transfer_confirmed call, unknown transfer handle";
        return;
    }

    pending_transfer_confirmation_timeout_->stop();

    if (!file_transfer_flow_->send_file(current_upload_))
    {
        LOG(ERROR) << "Cannot send file, abandoning upload procedure";
        upload_state_ = UploadState::IDLE;
        current_upload_.clear();
        return;
    }

    upload_state_ = UploadState::UPLOADING;
}

void SANDNodeImpl::on_file_transfer_flow_state_changed(flows::FileTransferFlow::State new_state)
{
    if (state() == State::STARTING && new_state == flows::FileTransferFlow::State::RUNNING)
    {
        cv_waiting_for_start_.notify_one();
    }
}

void SANDNodeImpl::on_transfer_progress_changed(
    const flows::TransferHandle &transfer_handle, size_t bytes_transferred, size_t total_bytes)
{
    {
        std::lock_guard lock {upload_procedure_mutex_};
        if (upload_state_ == UploadState::UPLOADING && transfer_handle == current_upload_)
        {
            // Upload progress change, ignore
            return;
        }
    }

    {
        std::lock_guard lock {mutex_};
        if (state_ != State::DOWNLOADING)
        {
            LOG(ERROR) << "Stray on_transfer_progress_changed callback, wrong state: "
                       << to_string(state_);
            return;
        }
        if (transfer_handle != current_download_)
        {
            LOG(ERROR) << "Stray on_transfer_progress_changed callback, unknown transfer handle";
            return;
        }
    }

    listener_group_.notify(
        &SANDNodeListener::on_transfer_progress_changed, bytes_transferred, total_bytes);
}

void SANDNodeImpl::on_transfer_completed(const flows::TransferHandle &transfer_handle)
{
    {
        std::lock_guard lock {upload_procedure_mutex_};
        if (upload_state_ == UploadState::UPLOADING && transfer_handle == current_upload_)
        {
            // Upload completed
            upload_state_ = UploadState::IDLE;
            current_upload_.clear();
        }
    }

    {
        std::lock_guard lock {mutex_};
        if (state_ != State::DOWNLOADING)
        {
            LOG(ERROR) << "Stray on_transfer_completed callback, wrong state: "
                       << to_string(state_);
            return;
        }
        if (transfer_handle != current_download_)
        {
            LOG(ERROR) << "Stray on_transfer_completed callback, unknown transfer handle";
            return;
        }
        current_download_.clear();
        latest_download_succeeded_ = true;
    }
    cv_waiting_for_download_completion_.notify_one();
}

void SANDNodeImpl::on_transfer_error(
    const flows::TransferHandle &transfer_handle, const std::string &error_string)
{
    {
        std::lock_guard lock {mutex_};
        if (state_ != State::DOWNLOADING)
        {
            LOG(ERROR) << "Stray on_transfer_error callback, wrong state: " << to_string(state_);
            return;
        }
        if (transfer_handle != current_download_)
        {
            LOG(ERROR) << "Stray on_transfer_error callback, unknown transfer handle";
            return;
        }
        current_download_.clear();
        latest_download_succeeded_ = false;
        latest_download_error_     = error_string;
    }
    cv_waiting_for_download_completion_.notify_one();
}
}  // namespace sand
