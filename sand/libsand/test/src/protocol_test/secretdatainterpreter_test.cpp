#include <gtest/gtest.h>

#include <cstdlib>
#include <ctime>

#include "protocoltestutils.hpp"
#include "secretdatainterpreterimpl.hpp"

#include "rsacipher_mock.hpp"

using namespace ::testing;
using namespace ::sand::protocol;
using namespace ::sand::network;
using namespace ::sand::crypto;

namespace
{
class SecretDataInterpreterTest : public Test
{
protected:
    void SetUp() override
    {
        std::srand(unsigned(std::time(nullptr)));
        rsa_mock_ = std::make_shared<NiceMock<RSACipherMock>>();
    }

    std::shared_ptr<RSACipherMock> rsa_mock_;
};
}  // namespace

TEST_F(SecretDataInterpreterTest, EncryptSecretData_OfferMessage)
{
    auto           encryption = [](uint8_t in) { return in ^ 0xff; };  // basic XOR encryption
    RSACipher::Key pubk       = "Nicolae si Nicoleta Guta - Am stiut sa lupt cu viata";

    OfferMessage::SecretData secret;
    secret.parts = {{conversion::to_ipv4_address("192.168.0.1"), 0x90020526, 0x40000},
        {conversion::to_ipv4_address("192.168.0.2"), 0xa0020526, 0x37000}};
    testutils::random_values(secret.transfer_key.begin(), secret.transfer_key.size());

    std::vector<uint8_t> expected;
    std::transform(secret.transfer_key.cbegin(), secret.transfer_key.cend(),
        std::back_inserter(expected), encryption);
    {
        std::vector<uint8_t> expected_part2 {0x02, 0x01, 0x00, 0xa8, 0xc0, 0x26, 0x05, 0x02, 0x90,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x02, 0x00, 0xa8, 0xc0, 0x26, 0x05,
            0x02, 0xa0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70, 0x03, 0x00};
        std::transform(expected_part2.cbegin(), expected_part2.cend(), std::back_inserter(expected),
            encryption);
    }

    EXPECT_CALL(*rsa_mock_, encrypt(pubk, _))
        .Times(1)
        .WillOnce([&](const RSACipher::Key &, const RSACipher::ByteVector &plain_text) {
            RSACipher::ByteVector encrypted;
            std::transform(
                plain_text.cbegin(), plain_text.cend(), std::back_inserter(encrypted), encryption);
            return encrypted;
        });

    SecretDataInterpreterImpl interpreter {rsa_mock_};
    auto                      bytes = interpreter.encrypt_offer_message(secret, pubk);

    EXPECT_EQ(bytes, expected);
}

MATCHER(FilePartDataEq, "Equality comparison for OfferMessage::SecretData::PartData")
{
    return std::get<0>(arg).drop_point == std::get<1>(arg).drop_point &&
           std::get<0>(arg).part_offset == std::get<1>(arg).part_offset &&
           std::get<0>(arg).part_size == std::get<1>(arg).part_size;
}

TEST_F(SecretDataInterpreterTest, DecryptSecretData_OfferMessage)
{
    auto           decryption = [](uint8_t in) { return in ^ 0xff; };  // basic XOR encryption
    RSACipher::Key prik       = "Costel Ciofu & Modjo - Ia uite cum vine-n tara";

    std::vector<OfferMessage::SecretData::PartData> parts = {
        {conversion::to_ipv4_address("192.168.0.1"), 0x90020526, 0x40000},
        {conversion::to_ipv4_address("192.168.0.2"), 0xa0020526, 0x37000}};

    TransferKey transfer_key;
    testutils::random_values(transfer_key.begin(), transfer_key.size());

    std::vector<uint8_t> bytes;
    std::transform(
        transfer_key.cbegin(), transfer_key.cend(), std::back_inserter(bytes), decryption);
    {
        std::vector<uint8_t> bytes_part2 {0x02, 0x01, 0x00, 0xa8, 0xc0, 0x26, 0x05, 0x02, 0x90,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x02, 0x00, 0xa8, 0xc0, 0x26, 0x05,
            0x02, 0xa0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70, 0x03, 0x00};
        std::transform(
            bytes_part2.cbegin(), bytes_part2.cend(), std::back_inserter(bytes), decryption);
    }

    EXPECT_CALL(*rsa_mock_, decrypt(prik, _))
        .Times(1)
        .WillOnce([&](const RSACipher::Key &, const RSACipher::ByteVector &cipher_text) {
            RSACipher::ByteVector decrypted;
            std::transform(cipher_text.cbegin(), cipher_text.cend(), std::back_inserter(decrypted),
                decryption);
            return decrypted;
        });

    SecretDataInterpreterImpl interpreter {rsa_mock_};
    auto [secret, ok] = interpreter.decrypt_offer_message(bytes, prik);

    EXPECT_TRUE(ok);
    EXPECT_EQ(secret.transfer_key, transfer_key);
    EXPECT_TRUE(std::equal(secret.parts.cbegin(), secret.parts.cend(), parts.cbegin(),
        [](const auto &part1, const auto &part2) {
            return part1.drop_point == part2.drop_point && part1.part_offset == part2.part_offset &&
                   part1.part_size == part2.part_size;
        }));
}

TEST_F(SecretDataInterpreterTest, DecryptSecretData_OfferMessage_Invalid)
{
    auto           decryption = [](uint8_t in) { return in ^ 0xff; };  // basic XOR encryption
    RSACipher::Key prik       = "Cristian Rizescu - Gata cu gagicile[profa: Monica Constantin]";

    TransferKey transfer_key;
    testutils::random_values(transfer_key.begin(), transfer_key.size());

    std::vector<uint8_t> bytes;
    std::transform(
        transfer_key.cbegin(), transfer_key.cend(), std::back_inserter(bytes), decryption);
    {
        std::vector<uint8_t> bytes_part2 {0x02, 0x01, 0x00, 0xa8, 0xc0, 0x26, 0x05, 0x02, 0x90,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x02, 0x00, 0xa8, 0xc0, 0x26, 0x05,
            0x02, 0xa0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70, 0x03, 0x00};
        std::transform(
            bytes_part2.cbegin(), bytes_part2.cend(), std::back_inserter(bytes), decryption);
    }
    bytes.resize(bytes.size() - 1);

    EXPECT_CALL(*rsa_mock_, decrypt(prik, _))
        .Times(1)
        .WillOnce([&](const RSACipher::Key &, const RSACipher::ByteVector &cipher_text) {
            RSACipher::ByteVector decrypted;
            std::transform(cipher_text.cbegin(), cipher_text.cend(), std::back_inserter(decrypted),
                decryption);
            return decrypted;
        });

    SecretDataInterpreterImpl interpreter {rsa_mock_};
    auto [secret, ok] = interpreter.decrypt_offer_message(bytes, prik);

    EXPECT_FALSE(ok);
}
