#include "testutils.hpp"

#include <chrono>
#include <thread>

namespace testutils
{
bool wait_for(const std::function<bool()> &predicate, unsigned timeout_ms)
{
    using namespace std::chrono;
    auto start = steady_clock::now();
    while (!predicate() &&
           (timeout_ms == 0 ||
               duration_cast<milliseconds>(steady_clock::now() - start).count() <= timeout_ms))
    {
        std::this_thread::yield();
    }
    return predicate();
}

sand::network::IPv4Address random_ip_address(sand::utils::Random &rng)
{
    using sand::network::IPv4Address;
    return (rng.next<IPv4Address>(255) << 24) | (rng.next<IPv4Address>(255) << 16) |
           (rng.next<IPv4Address>(255) << 8) | (rng.next<IPv4Address>(255));
}

auto make_basic_reply_generator(bool ok)
    -> std::function<std::future<std::unique_ptr<sand::protocol::BasicReply>>(
        sand::network::IPv4Address, std::unique_ptr<sand::protocol::Message>)>
{
    using namespace sand::protocol;
    return [=](sand::network::IPv4Address, std::unique_ptr<Message> msg) {
        std::promise<std::unique_ptr<BasicReply>> promise;

        auto reply         = std::make_unique<BasicReply>(msg->message_code);
        reply->request_id  = msg->request_id;
        reply->status_code = ok ? StatusCode::OK : StatusCode::UNREACHABLE;
        promise.set_value(std::move(reply));

        return promise.get_future();
    };
}
}  // namespace testutils
