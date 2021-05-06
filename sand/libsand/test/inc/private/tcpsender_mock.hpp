#ifndef SAND_TEST_TCPSENDER_MOCK_HPP_
#define SAND_TEST_TCPSENDER_MOCK_HPP_

#include <gmock/gmock.h>

#include "tcpsender.hpp"

using namespace sand::network;

class TCPSenderMock : public TCPSender
{
public:
    MOCK_METHOD(bool, send, (IPv4Address, const uint8_t *, size_t), (override));
};

#endif  // SAND_TEST_TCPSENDER_MOCK_HPP_
