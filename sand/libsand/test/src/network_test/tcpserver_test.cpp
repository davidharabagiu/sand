#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>

#include "address.hpp"
#include "tcpserverimpl.hpp"

#include "tcpmessagelistener_mock.hpp"

using namespace ::testing;
using namespace ::boost::asio;
using namespace ::boost::asio::ip;
using namespace ::boost::system;
using namespace ::sand::network;

namespace
{
class TCPServerTest : public Test
{
protected:
    void SetUp() override
    {
        listener_mock_ = std::make_shared<NiceMock<TCPMessageListenerMock>>();
    }

    io_context                              server_context_;
    io_context                              sender_context_;
    std::shared_ptr<TCPMessageListenerMock> listener_mock_;
    const unsigned short                    port_ = 1234;
};
}  // namespace

TEST_F(TCPServerTest, ReceiveMessage)
{
    TCPServerImpl server {server_context_, port_};
    server.register_listener(listener_mock_);
    std::thread server_thread {[&] { server_context_.run(); }};

    const std::string       msg {"Eu cand beau fac prostii"};
    bool                    msg_received = false;
    std::mutex              mut;
    std::condition_variable cv;

    EXPECT_CALL(
        *listener_mock_, on_message_received(conversion::to_ipv4_address("127.0.0.1"), _, _))
        .With(Args<1, 2>(ElementsAreArray(msg.begin(), msg.end())))
        .Times(1)
        .WillOnce([&](...) {
            {
                std::lock_guard lock(mut);
                msg_received = true;
            }
            cv.notify_one();
        });

    tcp::socket socket {sender_context_};
    socket.connect({address::from_string("127.0.0.1"), port_});
    error_code err;
    write(socket, buffer(msg), err);
    EXPECT_FALSE(err);
    socket.close();

    {
        std::unique_lock lock {mut};
        cv.wait_for(lock, std::chrono::milliseconds {100}, [&] { return msg_received; });
    }
    EXPECT_TRUE(msg_received);

    server_context_.stop();
    server_thread.join();
}
