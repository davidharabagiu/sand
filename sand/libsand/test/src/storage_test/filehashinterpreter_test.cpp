#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <fstream>

#include "filehashinterpreterimpl.hpp"
#include "mainexecuter.hpp"
#include "random.hpp"

#include "base64encoder_mock.hpp"
#include "sha3hasher_mock.hpp"

using namespace ::testing;
using namespace ::sand::storage;
using namespace ::sand::protocol;
using namespace ::sand::utils;

namespace
{
class FileHashInterpreterTest : public Test
{
protected:
    void SetUp() override
    {
        b64_  = new NiceMock<Base64EncoderMock>();
        sha3_ = new NiceMock<SHA3HasherMock>();
    }

    Base64EncoderMock *b64_;
    SHA3HasherMock *   sha3_;
    Random             rng_;
    MainExecuter       executer_;
};
}  // namespace

TEST_F(FileHashInterpreterTest, Encode)
{
    AHash bin_hash;
    std::generate(bin_hash.begin(), bin_hash.end(), [&] { return rng_.next<Byte>(); });
    const std::string b64_hash {"manele 2021"};

    ON_CALL(*b64_, encode(_, _))
        .With(Args<0, 1>(ElementsAreArray(bin_hash)))
        .WillByDefault(Return(b64_hash));

    FileHashInterpreterImpl fhi {
        std::unique_ptr<Base64Encoder>(b64_), std::unique_ptr<SHA3Hasher>(sha3_)};
    EXPECT_EQ(b64_hash, fhi.encode(bin_hash));
}

TEST_F(FileHashInterpreterTest, Decode)
{
    AHash bin_hash;
    std::generate(bin_hash.begin(), bin_hash.end(), [&] { return rng_.next<Byte>(); });
    const std::string b64_hash {"manele 2021"};

    ON_CALL(*b64_, decode(b64_hash))
        .WillByDefault(Return(std::vector<Byte>(bin_hash.cbegin(), bin_hash.cend())));

    FileHashInterpreterImpl fhi {
        std::unique_ptr<Base64Encoder>(b64_), std::unique_ptr<SHA3Hasher>(sha3_)};
    AHash result;
    EXPECT_TRUE(fhi.decode(b64_hash, result));
    EXPECT_EQ(result, bin_hash);
}

TEST_F(FileHashInterpreterTest, Decode_InvalidInput)
{
    const std::string b64_hash {"manele 2021"};

    ON_CALL(*b64_, decode(b64_hash)).WillByDefault(Return(std::vector<Byte> {}));

    FileHashInterpreterImpl fhi {
        std::unique_ptr<Base64Encoder>(b64_), std::unique_ptr<SHA3Hasher>(sha3_)};
    AHash result;
    EXPECT_FALSE(fhi.decode(b64_hash, result));
}

TEST_F(FileHashInterpreterTest, GetFileSize)
{
    AHash             bin_hash;
    std::vector<Byte> bytes {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    std::copy(bytes.begin(), bytes.end(), bin_hash.data() + 64 + 28);

    FileHashInterpreterImpl fhi {
        std::unique_ptr<Base64Encoder>(b64_), std::unique_ptr<SHA3Hasher>(sha3_)};
    EXPECT_EQ(fhi.get_file_size(bin_hash), 0x0807060504030201);
}

TEST_F(FileHashInterpreterTest, CreateHash)
{
    const std::string file_path = "test/lorem_ipsum.txt";
    const std::string file_name = "lorem_ipsum.txt";

    std::vector<Byte> content_hash(64);
    std::generate(content_hash.begin(), content_hash.end(), [&] { return rng_.next<Byte>(); });
    std::vector<Byte> name_hash(28);
    std::generate(name_hash.begin(), name_hash.end(), [&] { return rng_.next<Byte>(); });

    size_t file_size;

    ON_CALL(*sha3_,
        hash(A<SHA3_512_t>(), WhenDynamicCastTo<std::ifstream &>(Truly([&](std::ifstream &fs) {
            fs.seekg(0, std::ios::end);
            file_size = size_t(fs.tellg());
            fs.seekg(0, std::ios::beg);
            return bool(fs);
        }))))
        .WillByDefault(Return(content_hash));
    ON_CALL(*sha3_, hash(An<SHA3_224_t>(), _, _))
        .With(Args<1, 2>(ElementsAreArray(file_name)))
        .WillByDefault(Return(name_hash));

    FileHashInterpreterImpl fhi {
        std::unique_ptr<Base64Encoder>(b64_), std::unique_ptr<SHA3Hasher>(sha3_)};
    AHash bin_hash;
    EXPECT_TRUE(fhi.create_hash(file_path, bin_hash, executer_).get());

    ASSERT_THAT(content_hash, ElementsAreArray(bin_hash.data(), content_hash.size()));
    ASSERT_THAT(
        name_hash, ElementsAreArray(bin_hash.data() + content_hash.size(), name_hash.size()));
    EXPECT_EQ(file_size, fhi.get_file_size(bin_hash));
}

TEST_F(FileHashInterpreterTest, CreateHash_InvalidFile)
{
    const std::string file_path = "test/wowmuch.file";

    FileHashInterpreterImpl fhi {
        std::unique_ptr<Base64Encoder>(b64_), std::unique_ptr<SHA3Hasher>(sha3_)};
    AHash bin_hash;
    EXPECT_FALSE(fhi.create_hash(file_path, bin_hash, executer_).get());
}
