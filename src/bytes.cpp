#include "vaultstorm/bytes.hpp"
#include <algorithm>
#include <cctype>
#include <sstream>

namespace vaultstorm {

std::string bytes_to_text(const uint8_t* data, size_t size) {
  std::string out;
  out.reserve(size);
  for (size_t i = 0; i < size; ++i) {
    unsigned char ch = data[i];
    if (ch == '\0') out.push_back('\n');
    else if (ch < 0x09) out.push_back(' ');
    else out.push_back(static_cast<char>(ch));
  }
  return out;
}

std::vector<uint8_t> to_bytes(const uint8_t* data, size_t size) {
  return std::vector<uint8_t>(data, data + size);
}

std::vector<std::string> split_lines(const std::string& input) {
  std::vector<std::string> lines;
  std::stringstream ss(input);
  std::string line;
  while (std::getline(ss, line)) lines.push_back(line);
  if (!input.empty() && input.back() == '\n') lines.push_back("");
  return lines;
}

std::vector<std::string> split(const std::string& input, char delim) {
  std::vector<std::string> parts;
  std::string current;
  for (char ch : input) {
    if (ch == delim) {
      parts.push_back(current);
      current.clear();
    } else {
      current.push_back(ch);
    }
  }
  parts.push_back(current);
  return parts;
}

std::string trim(std::string value) {
  auto is_space = [](unsigned char c) { return std::isspace(c) != 0; };
  value.erase(value.begin(), std::find_if(value.begin(), value.end(), [&](char c) {
    return !is_space(static_cast<unsigned char>(c));
  }));
  value.erase(std::find_if(value.rbegin(), value.rend(), [&](char c) {
    return !is_space(static_cast<unsigned char>(c));
  }).base(), value.end());
  return value;
}

std::string lower(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return value;
}

bool starts_with(const std::string& text, const std::string& prefix) {
  return text.size() >= prefix.size() && text.compare(0, prefix.size(), prefix) == 0;
}

bool contains_token(const std::string& text, const std::string& token) {
  auto pos = lower(text).find(lower(token));
  if (pos == std::string::npos) return false;
  bool left = pos == 0 || !std::isalnum(static_cast<unsigned char>(text[pos - 1]));
  size_t right_pos = pos + token.size();
  bool right = right_pos >= text.size() || !std::isalnum(static_cast<unsigned char>(text[right_pos]));
  return left && right;
}

uint32_t fnv1a(const std::string& text) {
  uint32_t h = 2166136261u;
  for (unsigned char c : text) {
    h ^= c;
    h *= 16777619u;
  }
  return h;
}

uint32_t read_u32_le(const std::vector<uint8_t>& data, size_t offset) {
  if (offset + 4 > data.size()) return 0;
  return static_cast<uint32_t>(data[offset]) |
         (static_cast<uint32_t>(data[offset + 1]) << 8) |
         (static_cast<uint32_t>(data[offset + 2]) << 16) |
         (static_cast<uint32_t>(data[offset + 3]) << 24);
}

}  // namespace vaultstorm
