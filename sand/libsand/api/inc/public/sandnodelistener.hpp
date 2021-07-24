#ifndef SAND_API_SANDNODELISTENER_HPP_
#define SAND_API_SANDNODELISTENER_HPP_

#include "sandapidefs.h"

namespace sand
{
class SAND_API SANDNodeListener
{
public:
    virtual ~SANDNodeListener() = default;

    virtual void on_file_found()                                                            = 0;
    virtual void on_transfer_progress_changed(size_t bytes_transferred, size_t total_bytes) = 0;
};
}  // namespace sand

#endif  // SAND_API_SANDNODELISTENER_HPP_
