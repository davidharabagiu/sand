#include <iostream>
#include <memory>

#include <glog/logging.h>

#include "sandnode.hpp"
#include "sandnodelistener.hpp"

class TestNodeListener : public sand::SANDNodeListener
{
public:
    void on_transfer_progress_changed(size_t /*bytes_transferred*/, size_t /*total_bytes*/) override
    {}
};

int main(int /*argc*/
    ,
    char **argv)
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
