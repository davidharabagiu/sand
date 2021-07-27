#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "aescipherimpl.hpp"
#include "testutils.hpp"
#include "threadpool.hpp"

using namespace ::testing;
using namespace ::sand::crypto;
using namespace ::sand::utils;

namespace
{
class AESCipherTest : public Test
{
protected:
    void SetUp() override
    {}

    void TestEncryptDecrypt(size_t data_size)
    {
        ThreadPool            executer;
        AESCipherImpl         aes;
        AESCipher::ByteVector key;
        AESCipher::ByteVector iv;

        EXPECT_TRUE(aes.generate_key_and_iv(AESCipher::AES128, AESCipher::CBC, key, iv));

        AESCipher::ByteVector original(data_size);
        testutils::random_values(original.begin(), original.size());

        auto encrypted = aes.encrypt(AESCipher::CBC, key, iv, original, executer).get();
        EXPECT_FALSE(encrypted.empty());

        auto decrypted = aes.decrypt(AESCipher::CBC, key, iv, encrypted, executer).get();
        EXPECT_FALSE(decrypted.empty());

        EXPECT_THAT(original, ContainerEq(decrypted));
    }
};
}  // namespace

TEST_F(AESCipherTest, GenerateKeyAndIV)
{
    AESCipherImpl         aes;
    AESCipher::ByteVector key;
    AESCipher::ByteVector iv;

    EXPECT_TRUE(aes.generate_key_and_iv(AESCipher::AES128, AESCipher::CBC, key, iv));
    EXPECT_EQ(key.size(), 16);
    EXPECT_EQ(iv.size(), 16);
}

TEST_F(AESCipherTest, EncryptDecrypt_NoPadding)
{
    TestEncryptDecrypt(16 * 1000);
}

TEST_F(AESCipherTest, EncryptDecrypt_Padding)
{
    TestEncryptDecrypt(16 * 1000 + 5);
}
