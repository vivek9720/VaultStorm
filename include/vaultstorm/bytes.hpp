#ifndef VAULTSTORM_BYTES_HPP
#define VAULTSTORM_BYTES_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace vaultstorm {

std::string bytes_to_text(const uint8_t* data, size_t size);
std::vector<std::string> split_lines(const std::string& input);
std::vector<std::string> split(const std::string& input, char delim);
std::string trim(std::string value);
std::string lower(std::string value);
bool starts_with(const std::string& text, const std::string& prefix);
bool contains_token(const std::string& text, const std::string& token);
uint32_t fnv1a(const std::string& text);
uint32_t read_u32_le(const std::vector<uint8_t>& data, size_t offset);
std::vector<uint8_t> to_bytes(const uint8_t* data, size_t size);

}  // namespace vaultstorm

#endif
