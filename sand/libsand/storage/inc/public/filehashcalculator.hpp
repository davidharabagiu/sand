#ifndef SAND_STORAGE_FILEHASHCALCULATOR_HPP_
#define SAND_STORAGE_FILEHASHCALCULATOR_HPP_

#include <cstdint>
#include <string>

namespace sand::storage
{
class FileHashCalculator
{
public:
    virtual ~FileHashCalculator() = default;

    virtual bool        decode(const std::string &in, uint8_t *out) = 0;
    virtual std::string encode(const uint8_t *in)                   = 0;
};
}  // namespace sand::storage

#endif  // SAND_STORAGE_FILEHASHCALCULATOR_HPP_
