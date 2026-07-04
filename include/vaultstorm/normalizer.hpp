#ifndef VAULTSTORM_NORMALIZER_HPP
#define VAULTSTORM_NORMALIZER_HPP

#include <map>
#include <string>
#include <vector>

namespace vaultstorm {

struct FieldMap {
  std::map<std::string, std::string> values;
  std::vector<std::string> order;
  void set(std::string key, std::string value);
  std::string get(const std::string& key) const;
  bool has(const std::string& key) const;
};

FieldMap parse_kv_lines(const std::string& text);
FieldMap parse_semicolon_record(const std::string& text);
std::string canonical_name(std::string key);
std::vector<std::string> parse_list(const std::string& text);

}  // namespace vaultstorm

#endif
