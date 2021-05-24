#ifndef SAND_FLOWS_FILELOCATORFLOW_HPP_
#define SAND_FLOWS_FILELOCATORFLOW_HPP_

#include <memory>
#include <string>

#include "searchhandle.hpp"

namespace sand::flows
{
class FileLocatorFlowListener;

class FileLocatorFlow
{
public:
    enum class State
    {
        IDLE,
        RUNNING,
        STOPPING
    };

    virtual ~FileLocatorFlow() = default;

    virtual void start()                                                                = 0;
    virtual void stop()                                                                 = 0;
    virtual bool register_listener(std::shared_ptr<FileLocatorFlowListener> listener)   = 0;
    virtual bool unregister_listener(std::shared_ptr<FileLocatorFlowListener> listener) = 0;
    [[nodiscard]] virtual State        state() const                                    = 0;
    [[nodiscard]] virtual SearchHandle search(const std::string &file_hash)             = 0;
    virtual bool                       cancel_search(const SearchHandle &search_handle) = 0;
};
}  // namespace sand::flows

#endif  // SAND_FLOWS_FILELOCATORFLOW_HPP_
