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
        return m_listeners.try_emplace(listener.get(), listener).second;
    }

    bool remove(const SharedPtrListener &listener)
    {
        return m_listeners.erase(listener.get());
    }

    template<typename M, typename... Args>
    void notify(M method, Args &&... args)
    {
        for (auto it = m_listeners.begin(); it != m_listeners.end();)
        {
            auto listener = it->second.lock();
            if (listener)
            {
                ((*listener).*method)(std::forward<Args>(args)...);
                ++it;
            }
            else
            {
                it = m_listeners.erase(it);
            }
        }
    }

private:
    using Key = void *;
    std::map<Key, WeakPtrListener> m_listeners;
};
}  // namespace sand::utils

#endif  // LIBSAND_UTILS_LISTENERGROUP_HPP_