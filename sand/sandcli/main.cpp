#include <iostream>

#include <glog/logging.h>

#include "sandnode.hpp"
#include "sandnodelistener.hpp"

class TestNodeListener : public sand::SANDNodeListener
{
public:
    void on_initialization_completed(bool success) override
    {
        if (!success)
        {
            std::cout << "Failed to initialize node, check the log file for details.\n";
        }
        else
        {
            std::cout << "SAND node initialized\n";
        }
    }

    void on_uninitialization_completed() override
    {
        std::cout << "SAND node uninitialized\n";
    }
};

int main(int /*argc*/, char **argv)
{
    google::InitGoogleLogging(argv[0]);

    sand::SANDNode node {"plm.json"};
    if (!node.initialize())
    {
        std::cout << "Failed to initialize node, check the log file for details.\n";
    }

    return 0;
}
