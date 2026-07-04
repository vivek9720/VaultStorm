#include "vaultstorm/normalizer.hpp"
#include "vaultstorm/bytes.hpp"

namespace vaultstorm {

void FieldMap::set(std::string key, std::string value) {
  key = canonical_name(trim(key));
  value = trim(value);
  if (!has(key)) order.push_back(key);
  values[key] = value;
}

std::string FieldMap::get(const std::string& key) const {
  auto it = values.find(canonical_name(key));
  return it == values.end() ? std::string() : it->second;
}

bool FieldMap::has(const std::string& key) const {
  return values.find(canonical_name(key)) != values.end();
}

std::string canonical_name(std::string key) {
  key = lower(trim(key));
  for (char& ch : key) {
    if (ch == '-' || ch == ' ') ch = '_';
  }
  return key;
}

FieldMap parse_kv_lines(const std::string& text) {
  FieldMap map;
  for (auto line : split_lines(text)) {
    line = trim(line);
    if (line.empty() || starts_with(line, "#")) continue;
    auto pos = line.find('=');
    if (pos == std::string::npos) pos = line.find(':');
    if (pos != std::string::npos) map.set(line.substr(0, pos), line.substr(pos + 1));
  }
  return map;
}

FieldMap parse_semicolon_record(const std::string& text) {
  FieldMap map;
  for (const auto& part : split(text, ';')) {
    auto pos = part.find('=');
    if (pos != std::string::npos) map.set(part.substr(0, pos), part.substr(pos + 1));
  }
  return map;
}

std::vector<std::string> parse_list(const std::string& text) {
  std::vector<std::string> out;
  for (auto part : split(text, ',')) {
    part = trim(part);
    if (!part.empty()) out.push_back(part);
  }
  return out;
}

}  // namespace vaultstorm
