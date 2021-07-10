#ifndef SAND_API_SANDNODELISTENER_HPP_
#define SAND_API_SANDNODELISTENER_HPP_

#include "sandapidefs.h"

namespace sand
{
class SAND_API SANDNodeListener
{
public:
    virtual ~SANDNodeListener() = default;

    virtual void on_initialization_completed(bool success) = 0;
    virtual void on_uninitialization_completed()           = 0;
};
}  // namespace sand

#endif  // SAND_API_SANDNODELISTENER_HPP_
