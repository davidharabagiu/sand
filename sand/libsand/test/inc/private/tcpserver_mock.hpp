#ifndef SAND_PROTOCOLTEST_TCPSERVER_MOCK_HPP_
#define SAND_PROTOCOLTEST_TCPSERVER_MOCK_HPP_

#include <gmock/gmock.h>

#include "tcpmessagelistener.hpp"
#include "tcpserver.hpp"

using namespace sand::network;

class TCPServerMock : public TCPServer
{
public:
    MOCK_METHOD(bool, register_listener, (std::shared_ptr<TCPMessageListener>), (override));
    MOCK_METHOD(bool, unregister_listener, (std::shared_ptr<TCPMessageListener>), (override));
};

#endif  // SAND_PROTOCOLTEST_TCPSERVER_MOCK_HPP_
