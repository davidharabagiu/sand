#include <gtest/gtest.h>

#include <fstream>
#include <iomanip>
#include <sstream>

#include "sha3hasherimpl.hpp"

using namespace ::testing;
using namespace ::sand::crypto;

namespace
{
class SHA3HasherTest : public Test
{
protected:
    static std::string bytes_to_hex(const std::vector<uint8_t> &bytes)
    {
        std::ostringstream ss;
        ss << std::hex;
        for (uint8_t byte : bytes)
        {
            ss << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        return ss.str();
    }

    const std::string str_ = "Society does not consist of individuals, but expresses the sum of "
                             "interrelations, the relations within which these individuals stand.";
    const uint8_t *   str_data_  = reinterpret_cast<const uint8_t *>(str_.data());
    const std::string test_file_ = "test/lorem_ipsum.txt";
};
}  // namespace

TEST_F(SHA3HasherTest, SHA3_224_HashBuffer)
{
    SHA3HasherImpl sha3;
    std::string    hash = bytes_to_hex(sha3.hash(SHA3_224, str_data_, str_.size()));
    EXPECT_EQ(hash, "865958350e96577ecfc0726064e4b3b5260b058708d4c108cffcb7c7");
}

TEST_F(SHA3HasherTest, SHA3_256_HashBuffer)
{
    SHA3HasherImpl sha3;
    std::string    hash = bytes_to_hex(sha3.hash(SHA3_256, str_data_, str_.size()));
    EXPECT_EQ(hash, "d72d9df35d377e7191339ffca71beefa2604d0ab1d56972e1540bd5886d7f0e3");
}

TEST_F(SHA3HasherTest, SHA3_384_HashBuffer)
{
    SHA3HasherImpl sha3;
    std::string    hash = bytes_to_hex(sha3.hash(SHA3_384, str_data_, str_.size()));
    EXPECT_EQ(hash, "30ff16debea866c2b4e2a5a99ba8476101d69c035f719a70171751133844513fe188e624fd5ed8"
                    "3885ae7598930c3d61");
}

TEST_F(SHA3HasherTest, SHA3_512_HashBuffer)
{
    SHA3HasherImpl sha3;
    std::string    hash = bytes_to_hex(sha3.hash(SHA3_512, str_data_, str_.size()));
    EXPECT_EQ(hash, "8cbc9fb6b7eaa3c306378e20df62dc2180439bd9f3ab846ebd4a1fecf996d1a201f8d209b82e8e"
                    "6bf5b1e5959001e905d12ea0f7baf6fe08f811c83b80fb00a6");
}

TEST_F(SHA3HasherTest, SHA3_224_HashStream)
{
    SHA3HasherImpl sha3;
    std::ifstream  fs {test_file_, std::ios::in | std::ios::binary};
    EXPECT_TRUE(fs.good());
    std::string hash = bytes_to_hex(sha3.hash(SHA3_224, fs));
    EXPECT_EQ(hash, "af6d57c93191204a6849257d4f796a4a21745f431eeee1617f1f0284");
}

TEST_F(SHA3HasherTest, SHA3_256_HashStream)
{
    SHA3HasherImpl sha3;
    std::ifstream  fs {test_file_, std::ios::in | std::ios::binary};
    EXPECT_TRUE(fs.good());
    std::string hash = bytes_to_hex(sha3.hash(SHA3_256, fs));
    EXPECT_EQ(hash, "a76fbc551903b9f59a26d45cc9b542936391feddc2bd8e08c41a0a47eeca02f7");
}

TEST_F(SHA3HasherTest, SHA3_384_HashStream)
{
    SHA3HasherImpl sha3;
    std::ifstream  fs {test_file_, std::ios::in | std::ios::binary};
    EXPECT_TRUE(fs.good());
    std::string hash = bytes_to_hex(sha3.hash(SHA3_384, fs));
    EXPECT_EQ(hash, "e3d709c0a15bf61e1ab70c2a4243b5bc52227e2a13cefffc5e031f396fc7b15c0ea08c8eea431f"
                    "d4ee5d082ff8c555ad");
}

TEST_F(SHA3HasherTest, SHA3_512_HashStream)
{
    SHA3HasherImpl sha3;
    std::ifstream  fs {test_file_, std::ios::in | std::ios::binary};
    EXPECT_TRUE(fs.good());
    std::string hash = bytes_to_hex(sha3.hash(SHA3_512, fs));
    EXPECT_EQ(hash, "d080dd8057e3c5afaf808641c0a8589b92bf9c76d5eaa0eaf904211aca50169e484b6f6cfdeb21"
                    "a89200239d05e0654f621b7c0ef2757bcedaa4cc1a8352e464");
}
