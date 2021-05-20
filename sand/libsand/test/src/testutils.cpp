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
}  // namespace testutils
