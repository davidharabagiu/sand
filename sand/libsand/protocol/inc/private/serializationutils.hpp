#ifndef SAND_PROTOCOL_SERIALIZATIONUTILS_HPP_
#define SAND_PROTOCOL_SERIALIZATIONUTILS_HPP_

#include <algorithm>
#include <iterator>
#include <type_traits>

#include <glog/logging.h>

namespace sand::protocol::serialization
{
template<typename T, typename OutputIt>
auto serialize_field(const T &field, OutputIt dest) -> std::enable_if_t<std::is_pod_v<T>, OutputIt>
{
    auto b = reinterpret_cast<const uint8_t *>(&field);
    auto e = b + sizeof(T);
#ifdef IS_BIG_ENDIAN
    return std::copy(std::make_reverse_iterator(e), std::make_reverse_iterator(b), dest);
#else
    return std::copy(b, e, dest);
#endif  // IS_BIG_ENDIAN
}

template<typename Iterator>
auto check_distance(Iterator begin, size_t dist, Iterator end)
    -> std::enable_if_t<std::is_same_v<typename std::iterator_traits<Iterator>::iterator_category,
                            std::random_access_iterator_tag>,
        bool>
{
    std::advance(begin, dist);
    if (std::distance(begin, end) < 0)
    {
        LOG(WARNING) << "Cannot read past end iterator";
        return false;
    }
    return true;
}

template<typename T, typename InputIt>
auto deserialize_field(T &field, InputIt src_begin, InputIt src_end, bool &ok)
    -> std::enable_if_t<std::is_pod_v<T>, InputIt>
{
    if (!check_distance(src_begin, sizeof(T), src_end))
    {
        ok = false;
        return src_begin;
    }

    auto dest = reinterpret_cast<uint8_t *>(&field);

#ifdef IS_BIG_ENDIAN
    std::copy_n(std::make_reverse_iterator(src_end), src_count, dest);
#else
    std::copy_n(src_begin, sizeof(T), dest);
#endif  // IS_BIG_ENDIAN
    std::advance(src_begin, sizeof(T));

    ok = true;
    return src_begin;
}
}  // namespace sand::protocol::serialization

#endif  // SAND_PROTOCOL_SERIALIZATIONUTILS_HPP_