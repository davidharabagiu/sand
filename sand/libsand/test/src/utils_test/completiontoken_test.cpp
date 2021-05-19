#include <gtest/gtest.h>

#include <mutex>
#include <thread>

#include "completiontoken.hpp"

using namespace ::testing;
using namespace ::sand::utils;

namespace
{
class CompletionTokenTest : public Test
{
};
}  // namespace

TEST_F(CompletionTokenTest, WaitForCompletion)
{
    CompletionToken token;
    bool            executed = false;

    std::thread t {[&executed, token]() {
        executed = true;
        token.complete();
    }};

    token.wait_for_completion();
    EXPECT_TRUE(executed);
    t.join();
}

TEST_F(CompletionTokenTest, Cancel)
{
    CompletionToken token;
    bool            executed = false;
    std::mutex      m;

    std::unique_lock l {m};

    std::thread t {[&executed, &m, token]() {
        {
            std::lock_guard l {m};
        }

        if (token.is_cancelled())
        {
            token.complete();
            return;
        }

        executed = true;
        token.complete();
    }};

    token.cancel();
    l.unlock();

    token.wait_for_completion();
    EXPECT_FALSE(executed);
    t.join();
}
