#ifndef LIBSAND_UTILS_LISTENERGROUP_HPP_
#define LIBSAND_UTILS_LISTENERGROUP_HPP_

#include <map>
#include <memory>
#include <mutex>
#include <utility>

namespace sand::utils
{
template<typename T>
class ListenerGroup
{
public:
    using Listener          = T;
    using SharedPtrListener = std::shared_ptr<Listener>;
    using WeakPtrListener   = std::weak_ptr<Listener>;

    bool add(const SharedPtrListener &listener)
    {
        std::lock_guard lock {mutex_};
        return listeners_.try_emplace(listener.get(), listener).second;
    }

    bool remove(const SharedPtrListener &listener)
    {
        std::lock_guard lock {mutex_};
        return listeners_.erase(listener.get());
    }

    template<typename M, typename... Args>
    void notify(M method, Args &&... args)
    {
        std::vector<SharedPtrListener> listeners_copy;

        {
            std::lock_guard lock {mutex_};

            listeners_copy.reserve(listeners_.size());
            for (auto it = listeners_.begin(); it != listeners_.end();)
            {
                auto listener = it->second.lock();
                if (listener)
                {
                    listeners_copy.push_back(listener);
                    ++it;
                }
                else
                {
                    it = listeners_.erase(it);
                }
            }
        }

        for (auto &listener : listeners_copy)
        {
            ((*listener).*method)(std::forward<Args>(args)...);
        }
    }

private:
    using Key = void *;
    std::map<Key, WeakPtrListener> listeners_;
    std::mutex                     mutex_;
};
}  // namespace sand::utils

#endif  // LIBSAND_UTILS_LISTENERGROUP_HPP_
