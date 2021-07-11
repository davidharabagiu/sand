#include <iostream>
#include <memory>

#include <glog/logging.h>

#include "sandnode.hpp"
#include "sandnodelistener.hpp"

class TestNodeListener : public sand::SANDNodeListener
{};

int main(int /*argc*/, char **argv)
{
    google::InitGoogleLogging(argv[0]);

    sand::SANDNode node {APP_DATA_DIR, "config.json"};
    auto           node_listener = std::make_shared<TestNodeListener>();
    node.register_listener(node_listener);

    /*if (!node.start())
    {
        std::cout << "Failed to start node, check the log file for details.\n";
    }*/

    return 0;
}
