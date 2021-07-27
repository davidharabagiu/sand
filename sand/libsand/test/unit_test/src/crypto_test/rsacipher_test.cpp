#include <gtest/gtest.h>

#include <cstdlib>
#include <ctime>

#include "rsacipherimpl.hpp"
#include "testutils.hpp"
#include "threadpool.hpp"

using namespace ::testing;
using namespace ::sand::utils;
using namespace ::sand::crypto;

namespace
{
class RSACipherTest : public Test
{
protected:
    void SetUp() override
    {
        std::srand(static_cast<unsigned int>(std::time(nullptr)));
    }

    void RunTest(Executer &executer, size_t data_size, int job_count)
    {
        RSACipherImpl rsa;

        RSACipher::Key public_key;
        RSACipher::Key private_key;
        EXPECT_TRUE(
            rsa.generate_key_pair(RSACipher::M512, RSACipher::E3, public_key, private_key, executer)
                .get());

        RSACipher::ByteVector original(data_size);
        testutils::random_values(original.begin(), original.size());

        auto encrypted = rsa.encrypt(public_key, original, executer, job_count).get();
        EXPECT_FALSE(encrypted.empty());

        auto decrypted = rsa.decrypt(private_key, encrypted, executer, job_count).get();
        EXPECT_FALSE(decrypted.empty());

        EXPECT_EQ(original, decrypted);
    }
};
}  // namespace

TEST_F(RSACipherTest, SingleProcessingBlock)
{
    ThreadPool executer;
    RunTest(executer, 32, 1);
}

TEST_F(RSACipherTest, MultipleProcessingBlocks_SingleJob)
{
    ThreadPool executer;
    RunTest(executer, 100000, 1);
}

TEST_F(RSACipherTest, MultipleProcessingBlocks_MultipleJobs_SingleThread)
{
    ThreadPool executer;
    RunTest(executer, 100000, 8);
}

TEST_F(RSACipherTest, MultipleProcessingBlocks_MultipleJobs_MultipleThreads)
{
    ThreadPool executer {8};
    RunTest(executer, 100000, 8);
}
