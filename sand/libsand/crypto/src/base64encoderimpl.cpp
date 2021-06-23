#include "base64encoderimpl.hpp"

#include <algorithm>
#include <limits>

#include <glog/logging.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>

namespace sand::crypto
{
std::string Base64EncoderImpl::encode(const Byte *data, size_t len)
{
    BIO *b64 = BIO_new(BIO_f_base64());
    if (!b64)
    {
        LOG(FATAL) << "BIO_new failed";
    }

    BIO *bmem = BIO_new(BIO_s_mem());
    if (!bmem)
    {
        LOG(FATAL) << "BIO_new failed";
    }
    bmem = BIO_push(b64, bmem);

    BIO_set_flags(bmem, BIO_FLAGS_BASE64_NO_NL);
    BIO_set_close(bmem, BIO_CLOSE);

    size_t written;
    if (!BIO_write_ex(b64, data, len, &written) || len != written)
    {
        LOG(FATAL) << "BIO_write_ex failed";
    }

    if (BIO_flush(b64) != 1)
    {
        LOG(FATAL) << "BIO_flush failed";
    }

    BUF_MEM *bptr;
    BIO_get_mem_ptr(bmem, &bptr);
    std::string out(bptr->data, bptr->length);

    BIO_free_all(bmem);
    return out;
}

std::vector<Base64Encoder::Byte> Base64EncoderImpl::decode(const std::string &data)
{
    constexpr auto max_data_len = size_t(std::numeric_limits<int>::max());
    size_t         data_len     = data.length();
    if (data_len > max_data_len)
    {
        LOG(ERROR) << "Input too large. Maximum supported is " << max_data_len << ".";
        data_len = max_data_len;
    }

    BIO *b64 = BIO_new(BIO_f_base64());
    if (!b64)
    {
        LOG(FATAL) << "BIO_new failed";
    }

    BIO *bmem = BIO_new_mem_buf(data.data(), int(data_len));
    if (!bmem)
    {
        LOG(FATAL) << "BIO_new failed";
    }
    bmem = BIO_push(b64, bmem);

    BIO_set_flags(bmem, BIO_FLAGS_BASE64_NO_NL);
    BIO_set_close(bmem, BIO_CLOSE);

    std::vector<Byte> out(data_len);
    size_t            out_len;
    if (!BIO_read_ex(bmem, out.data(), data_len, &out_len))
    {
        LOG(FATAL) << "BIO_read_ex failed";
    }
    out.resize(out_len);

    BIO_free_all(bmem);
    return out;
}
}  // namespace sand::crypto
