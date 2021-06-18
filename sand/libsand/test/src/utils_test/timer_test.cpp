#include <gtest/gtest.h>

#include <chrono>
#include <cmath>
#include <condition_variable>
#include <mutex>

#include "iothreadpool.hpp"
#include "timer.hpp"

using namespace ::testing;
using namespace ::sand::utils;

namespace
{
class TimerTest : public Test
{
protected:
    void SetUp() override
    {
        executer_ = std::make_shared<IOThreadPool>();
    }

    static auto now()
    {
        return std::chrono::steady_clock::now();
    }

    template<typename Int, typename Float>
    static constexpr Int round(Float x)
    {
        return Int(x + 0.5);
    }

    std::shared_ptr<Executer> executer_;
};
}  // namespace

TEST_F(TimerTest, SingleShot)
{
    constexpr std::chrono::milliseconds period {100};
    constexpr float                     acceptable_error = 0.025f;
    constexpr std::chrono::milliseconds timeout {
        round<long>(period.count() * (1 + acceptable_error))};

    Timer                     timer {executer_};
    bool                      called = false;
    std::mutex                mut;
    std::condition_variable   cv;
    std::chrono::milliseconds actual_period;

    auto start = now();
    EXPECT_TRUE(timer.start(
        period,
        [&] {
            actual_period = std::chrono::duration_cast<decltype(actual_period)>(now() - start);
            {
                std::lock_guard lock {mut};
                called = true;
            }
            cv.notify_one();
        },
        true));

    std::unique_lock lock {mut};
    EXPECT_TRUE(cv.wait_for(lock, timeout, [&] { return called; }));
    EXPECT_LE(std::fabs(float(actual_period.count()) / period.count() - 1), acceptable_error);
}

TEST_F(TimerTest, SingleShot_Stop)
{
    constexpr std::chrono::milliseconds period {50};

    Timer timer {executer_};
    bool  called = false;

    EXPECT_TRUE(timer.start(
        period, [&] { called = true; }, true));
    std::this_thread::yield();  // Let the wait job start

    EXPECT_TRUE(timer.stop());  // This call blocks until the wait job expires
    EXPECT_FALSE(called);
}

TEST_F(TimerTest, Periodic)
{
    constexpr std::chrono::milliseconds period {50};
    constexpr float                     acceptable_error = 0.025f;
    constexpr std::chrono::milliseconds timeout {
        round<long>(period.count() * (1 + acceptable_error))};
    constexpr int iterations = 3;

    Timer                     timer {executer_};
    bool                      called = false;
    std::mutex                mut;
    std::condition_variable   cv;
    std::chrono::milliseconds actual_period;

    auto start = now();
    EXPECT_TRUE(timer.start(
        period,
        [&] {
            {
                std::lock_guard lock {mut};
                actual_period = std::chrono::duration_cast<decltype(actual_period)>(now() - start);
                called        = true;
            }
            cv.notify_one();
        },
        false));

    for (int i = 0; i != iterations; ++i)
    {
        std::unique_lock lock {mut};
        EXPECT_TRUE(cv.wait_for(lock, timeout, [&] { return called; }));
        start  = now();
        called = false;
        lock.unlock();
        EXPECT_LE(std::fabs(float(actual_period.count()) / period.count() - 1), acceptable_error);
    }

    EXPECT_TRUE(timer.stop());  // This call blocks until the wait job expires
    EXPECT_FALSE(called);
}

TEST_F(TimerTest, DoubleStart)
{
    constexpr std::chrono::milliseconds period {50};
    constexpr float                     error = 0.025f;
    constexpr std::chrono::milliseconds timeout {round<long>(period.count() * (1 + error))};

    Timer                   timer {executer_};
    bool                    called = false;
    std::mutex              mut;
    std::condition_variable cv;

    EXPECT_TRUE(timer.start(
        period,
        [&] {
            {
                std::lock_guard lock {mut};
                called = true;
            }
            cv.notify_one();
        },
        true));

    EXPECT_FALSE(timer.start(
        period, [] {}, true));

    std::unique_lock lock {mut};
    EXPECT_TRUE(cv.wait_for(lock, timeout, [&] { return called; }));

    EXPECT_TRUE(timer.start(
        period, [] {}, true));
}

TEST_F(TimerTest, DoubleStop)
{
    constexpr std::chrono::milliseconds period {50};

    Timer timer {executer_};

    EXPECT_TRUE(timer.start(period, [] {}));

    EXPECT_TRUE(timer.stop());
    EXPECT_FALSE(timer.stop());
}

TEST_F(TimerTest, Restart)
{
    constexpr std::chrono::milliseconds period {100};
    constexpr std::chrono::milliseconds restart_delay {50};
    constexpr float                     acceptable_error = 0.025f;
    constexpr std::chrono::milliseconds timeout {
        round<long>((period.count() + restart_delay.count()) * (1 + acceptable_error))};

    Timer                     timer {executer_};
    bool                      called = false;
    std::mutex                mut;
    std::condition_variable   cv;
    std::chrono::milliseconds actual_period;

    auto start = now();
    EXPECT_TRUE(timer.start(
        period,
        [&] {
            actual_period = std::chrono::duration_cast<decltype(actual_period)>(now() - start);
            {
                std::lock_guard lock {mut};
                called = true;
            }
            cv.notify_one();
        },
        true));

    std::this_thread::sleep_for(restart_delay);
    timer.restart();

    std::unique_lock lock {mut};
    EXPECT_TRUE(cv.wait_for(lock, timeout, [&] { return called; }));
    EXPECT_LE(
        std::fabs(float(actual_period.count()) / (period.count() + restart_delay.count()) - 1),
        acceptable_error);
}
