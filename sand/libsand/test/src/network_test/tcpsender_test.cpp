#include <gtest/gtest.h>

#include <condition_variable>
#include <memory>
#include <string>
#include <thread>

#include <boost/asio.hpp>

#include "tcpsenderimpl.hpp"

using namespace ::testing;
using namespace ::boost::system;
using namespace ::boost::asio;
using namespace ::boost::asio::ip;
using namespace ::sand::network;

namespace
{
class TCPSenderTest : public Test
{
protected:
    void SetUp() override
    {
        listener_ = std::make_unique<tcp::acceptor>(listener_context_, tcp::endpoint {{}, port_});
        listener_->set_option(tcp::acceptor::reuse_address {true});
        listener_->listen();
    }

    io_context                     sender_context_;
    io_context                     listener_context_;
    std::unique_ptr<tcp::acceptor> listener_;
    const unsigned short           port_ = 1234;
};
}  // namespace

#include <iostream>

TEST_F(TCPSenderTest, SendMessage)
{
    const std::string msg_to_send {"Drobeta-Turnu Severin"};

    bool                    message_received = false;
    std::mutex              m;
    std::condition_variable cv;

    listener_->async_accept([&](const error_code &ec, tcp::socket socket) {
        EXPECT_FALSE(ec);
        EXPECT_EQ(socket.remote_endpoint().address().to_string(), "127.0.0.1");

        char data[128];
        data[socket.read_some(buffer(data, 128))] = '\0';

        EXPECT_EQ(std::string(data), msg_to_send);
        {
            std::lock_guard<std::mutex> lock {m};
            message_received = true;
        }
        cv.notify_one();
    });

    std::thread t_ctx_listener {[&] { listener_context_.run(); }};

    TCPSenderImpl sender {sender_context_};

    auto send_status_future = sender.send(conversion::to_ipv4_address("127.0.0.1"), port_,
        reinterpret_cast<const uint8_t *>(msg_to_send.data()), msg_to_send.size());

    std::thread t_ctx_sender {[&] { sender_context_.run(); }};

    EXPECT_TRUE(send_status_future.get());

    std::unique_lock<std::mutex> lock {m};
    cv.wait_for(lock, std::chrono::milliseconds {10000}, [&] { return message_received; });
    EXPECT_TRUE(message_received);

    t_ctx_sender.join();
    t_ctx_listener.join();
}

TEST_F(TCPSenderTest, SendMessage_InvalidDestinationEndpoint)
{
    const std::string msg_to_send {"Drobeta-Turnu Severin"};

    bool                    message_received = false;
    std::mutex              m;
    std::condition_variable cv;

    listener_->async_accept([&](const error_code & /*ec*/, tcp::socket /*socket*/) {
        {
            std::lock_guard<std::mutex> lock {m};
            message_received = true;
        }
        cv.notify_one();
    });

    std::thread t_ctx_listener {[&] { listener_context_.run(); }};

    TCPSenderImpl sender {sender_context_};

    auto send_status_future = sender.send(conversion::to_ipv4_address("127.0.0.1"),
        static_cast<unsigned short>(port_ + 1),
        reinterpret_cast<const uint8_t *>(msg_to_send.data()), msg_to_send.size());

    std::thread t_ctx_sender {[&] { sender_context_.run(); }};

    EXPECT_FALSE(send_status_future.get());

    std::unique_lock<std::mutex> lock {m};
    cv.wait_for(lock, std::chrono::milliseconds {100}, [&] { return message_received; });
    EXPECT_FALSE(message_received);

    listener_context_.stop();
    t_ctx_sender.join();
    t_ctx_listener.join();
}
