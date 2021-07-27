#include <gtest/gtest.h>

#include <memory>

#include "base64encoderimpl.hpp"

using namespace ::testing;
using namespace ::sand::crypto;

namespace
{
class Base64EncoderTest : public Test
{
protected:
    const std::string text_ = "When we are tired, we are attacked by ideas we conquered long ago.";
    const std::string text_b64_ =
        "V2hlbiB3ZSBhcmUgdGlyZWQsIHdlIGFyZSBhdHRhY2tlZCBieSBpZGVhcyB3ZSBjb25xdWVyZWQgbG9uZyBhZ28u";
};
}  // namespace

TEST_F(Base64EncoderTest, Encode)
{
    Base64EncoderImpl b64;
    std::string enc = b64.encode(reinterpret_cast<const uint8_t *>(text_.data()), text_.length());
    EXPECT_EQ(enc, text_b64_);
}

TEST_F(Base64EncoderTest, Decode)
{
    Base64EncoderImpl    b64;
    std::vector<uint8_t> dec = b64.decode(text_b64_);
    EXPECT_EQ(std::string(reinterpret_cast<const char *>(dec.data()), dec.size()), text_);
}
