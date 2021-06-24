#ifndef SAND_STORAGE_FILEHASHINTERPRETERIMPL_HPP_
#define SAND_STORAGE_FILEHASHINTERPRETERIMPL_HPP_

#include "executer.hpp"
#include "filehashinterpreter.hpp"

namespace sand::crypto
{
// Forward declarations
class Base64Encoder;
class SHA3Hasher;
}  // namespace sand::crypto

namespace sand::storage
{
class FileHashInterpreterImpl : public FileHashInterpreter
{
public:
    FileHashInterpreterImpl(
        std::unique_ptr<crypto::Base64Encoder> b64, std::unique_ptr<crypto::SHA3Hasher> sha3);
    ~FileHashInterpreterImpl() override;

    bool                      decode(const std::string &in, protocol::AHash &out) const override;
    [[nodiscard]] std::string encode(const protocol::AHash &in) const override;
    [[nodiscard]] size_t      get_file_size(const protocol::AHash &file_hash) const override;
    [[nodiscard]] std::future<bool> create_hash(const std::string &file_path, protocol::AHash &out,
        utils::Executer &executer) const override;

private:
    const std::unique_ptr<crypto::Base64Encoder> b64_;
    const std::shared_ptr<crypto::SHA3Hasher>    sha3_;
};
}  // namespace sand::storage

#endif  // SAND_STORAGE_FILEHASHINTERPRETERIMPL_HPP_
