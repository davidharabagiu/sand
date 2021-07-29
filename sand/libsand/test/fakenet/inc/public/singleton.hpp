#ifndef SAND_TEST_FAKENET_SINGLETON_HPP_
#define SAND_TEST_FAKENET_SINGLETON_HPP_

#include <memory>
#include <mutex>

template<typename T>
class Singleton
{
public:
    Singleton() = delete;

    static T &get()
    {
        std::lock_guard lock {mutex_};
        if (!instance_)
        {
            instance_ = std::make_unique<T>();
        }
        return *instance_;
    }

    static void reset()
    {
        std::lock_guard lock {mutex_};
        instance_.reset();
    }

private:
    static std::unique_ptr<T> instance_;
    static std::mutex         mutex_;
};

template<typename T>
std::unique_ptr<T> Singleton<T>::instance_;

template<typename T>
std::mutex Singleton<T>::mutex_;

#endif  // SAND_TEST_FAKENET_SINGLETON_HPP_
