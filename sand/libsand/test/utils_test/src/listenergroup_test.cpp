#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "listenergroup.hpp"

using namespace ::testing;
using sand::utils::ListenerGroup;

namespace
{
class TestListener
{
public:
    virtual ~TestListener()                                       = default;
    virtual void Notification1()                                  = 0;
    virtual void Notification2()                                  = 0;
    virtual void Notification3(int arg1, const std::string &arg2) = 0;
};

class TestListenerImpl : public TestListener
{
public:
    MOCK_METHOD(void, Notification1, (), (override));
    MOCK_METHOD(void, Notification2, (), (override));
    MOCK_METHOD(void, Notification3, (int arg1, const std::string &arg2), (override));
};

class ListenerGroupTest : public Test
{
protected:
    void SetUp() override
    {
        m_listener_mock.reset(new NiceMock<TestListenerImpl>());
    }

    std::shared_ptr<TestListenerImpl> m_listener_mock;
};

}  // namespace

TEST_F(ListenerGroupTest, CorrectNotification)
{
    EXPECT_CALL(*m_listener_mock, Notification1()).Times(1);
    EXPECT_CALL(*m_listener_mock, Notification2()).Times(0);

    ListenerGroup<TestListener> group;
    group.Add(m_listener_mock);
    group.Notify(&TestListener::Notification1);
}

TEST_F(ListenerGroupTest, MultipleListeners)
{
    const size_t kNumberOfListeners = 10;

    ListenerGroup<TestListener> group;

    std::vector<std::shared_ptr<TestListenerImpl>> listeners(kNumberOfListeners);
    for (auto &l : listeners)
    {
        l.reset(new NiceMock<TestListenerImpl>());
        EXPECT_CALL(*l, Notification1()).Times(1);
        group.Add(l);
    }

    group.Notify(&TestListener::Notification1);
}

TEST_F(ListenerGroupTest, WithArguments)
{
    const int         kArg1 = 7;
    const std::string kArg2 = "my argument";

    EXPECT_CALL(*m_listener_mock, Notification3(kArg1, kArg2)).Times(1);

    ListenerGroup<TestListener> group;
    group.Add(m_listener_mock);
    group.Notify(&TestListener::Notification3, kArg1, kArg2);
}

TEST_F(ListenerGroupTest, MultipleCalls)
{
    const int kNumberOfCalls = 10;

    EXPECT_CALL(*m_listener_mock, Notification1()).Times(10);

    ListenerGroup<TestListener> group;
    group.Add(m_listener_mock);

    for (int i = 0; i != kNumberOfCalls; ++i)
    {
        group.Notify(&TestListener::Notification1);
    }
}

TEST_F(ListenerGroupTest, RemoveListener)
{
    auto second_listener = std::make_shared<NiceMock<TestListenerImpl>>();
    EXPECT_CALL(*m_listener_mock, Notification1()).Times(2);
    EXPECT_CALL(*second_listener, Notification1()).Times(1);

    ListenerGroup<TestListener> group;
    group.Add(m_listener_mock);
    group.Add(second_listener);
    group.Notify(&TestListener::Notification1);

    group.Remove(second_listener);
    group.Notify(&TestListener::Notification1);
}

TEST_F(ListenerGroupTest, AutoRemoveDestroyedListeners)
{
    auto second_listener = std::make_shared<NiceMock<TestListenerImpl>>();
    EXPECT_CALL(*m_listener_mock, Notification1()).Times(1);
    EXPECT_CALL(*second_listener, Notification1()).Times(0);

    ListenerGroup<TestListener> group;
    group.Add(m_listener_mock);
    group.Add(second_listener);
    second_listener.reset();

    // Expect no crash
    group.Notify(&TestListener::Notification1);
}
