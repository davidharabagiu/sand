#ifndef LIBSAND_UTILS_LISTENERGROUP_HPP_
#define LIBSAND_UTILS_LISTENERGROUP_HPP_

#include <map>
#include <memory>
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
        return listeners_.try_emplace(listener.get(), listener).second;
    }

    bool remove(const SharedPtrListener &listener)
    {
        return listeners_.erase(listener.get());
    }

    template<typename M, typename... Args>
    void notify(M method, Args &&... args)
    {
        for (auto it = listeners_.begin(); it != listeners_.end();)
        {
            auto listener = it->second.lock();
            if (listener)
            {
                ((*listener).*method)(std::forward<Args>(args)...);
                ++it;
            }
            else
            {
                it = listeners_.erase(it);
            }
        }
    }

private:
    using Key = void *;
    std::map<Key, WeakPtrListener> listeners_;
};
}  // namespace sand::utils

#endif  // LIBSAND_UTILS_LISTENERGROUP_HPP_
