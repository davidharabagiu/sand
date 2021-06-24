#include "filehashinterpreterimpl.hpp"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iterator>

#include <glog/logging.h>

#include "base64encoder.hpp"
#include "defer.hpp"
#include "sha3hasher.hpp"
#include "unused.hpp"

namespace sand::storage
{
FileHashInterpreterImpl::FileHashInterpreterImpl(
    std::unique_ptr<crypto::Base64Encoder> b64, std::unique_ptr<crypto::SHA3Hasher> sha3)
    : b64_ {std::move(b64)}
    , sha3_ {std::move(sha3)}
{}

FileHashInterpreterImpl::~FileHashInterpreterImpl()
{
    /*
     * Explicitly define destructor inside .cpp to avoid implicit calls to the incomplete type
     * Base64Encoder destructor due to storing it inside unique_ptr.
     */
}

bool FileHashInterpreterImpl::decode(const std::string &in, protocol::AHash &out) const
{
    std::vector<protocol::Byte> decoded = b64_->decode(in);
    if (decoded.size() != out.size())
    {
        return false;
    }
    std::copy(decoded.cbegin(), decoded.cend(), out.begin());
    return true;
}

std::string FileHashInterpreterImpl::encode(const protocol::AHash &in) const
{
    return b64_->encode(in.data(), in.size());
}

size_t FileHashInterpreterImpl::get_file_size(const protocol::AHash &file_hash) const
{
    constexpr size_t file_size_field_offset = (512 + 224) / 8;
    constexpr size_t file_size_field_length = 8;

    std::vector<uint8_t> size_bytes(file_hash.data() + file_size_field_offset,
        file_hash.data() + file_size_field_offset + file_size_field_length);
    size_t               file_size = 0;

#ifdef IS_BIG_ENDIAN
    std::copy(
        std::make_reverse_iterator(size_bytes.cend()), 8, reinterpret_cast<uint8_t *>(&file_size));
#else
    std::copy_n(size_bytes.cbegin(), 8, reinterpret_cast<uint8_t *>(&file_size));
#endif  // IS_BIG_ENDIAN

    return file_size;
}

std::future<bool> FileHashInterpreterImpl::create_hash(
    const std::string &file_path, protocol::AHash &out, utils::Executer &executer) const
{
    constexpr size_t file_size_field_length = 8;
    auto             promise                = std::make_shared<std::promise<bool>>();
    auto             sha3                   = sha3_;

    executer.add_job([file_path, promise, sha3, &out](const auto &completion_token) {
        bool success = false;
        DEFER(promise->set_value(success));

        std::ifstream fs {file_path, std::ios::in | std::ios::binary};
        if (!fs)
        {
            LOG(ERROR) << "Cannot open file " << file_path << " for reading.";
            return;
        }

        fs.seekg(0, std::ios::end);
        auto file_size = size_t(fs.tellg());
        fs.seekg(0, std::ios::beg);

        std::vector<uint8_t> content_hash {sha3->hash(crypto::SHA3_512, fs)};
        fs.close();

        if (completion_token.is_cancelled())
        {
            return;
        }

        std::string          file_name = std::filesystem::path {file_path}.filename().string();
        std::vector<uint8_t> name_hash {sha3->hash(
            crypto::SHA3_224, reinterpret_cast<uint8_t *>(file_name.data()), file_name.size())};

        std::vector<uint8_t> size_bytes(file_size_field_length);
#ifdef IS_BIG_ENDIAN
        std::copy_n(reinterpret_cast<uint8_t *>(&file_size), file_size_field_length,
            std::make_reverse_iterator(size_bytes.end()));
#else
        std::copy_n(
            reinterpret_cast<uint8_t *>(&file_size), file_size_field_length, size_bytes.begin());
#endif  // IS_BIG_ENDIAN

        std::copy(size_bytes.cbegin(), size_bytes.cend(),
            std::copy(name_hash.cbegin(), name_hash.cend(),
                std::copy(content_hash.cbegin(), content_hash.cend(), out.begin())));

        success = true;
    });

    return promise->get_future();
}
}  // namespace sand::storage
