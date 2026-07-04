#ifndef VAULTSTORM_TOKEN_HPP
#define VAULTSTORM_TOKEN_HPP

#include "vaultstorm/result.hpp"
#include "vaultstorm/normalizer.hpp"
#include <string>
#include <vector>

namespace vaultstorm {

struct TokenBundle {
  FieldMap fields;
  std::vector<std::string> records;
  std::string raw;
  int nesting = 0;
  int entropy = 0;
};

TokenBundle parse_token(const std::string& text);
AnalysisResult evaluate_token_bundle(const TokenBundle& document);
AnalysisResult analyze_token_bytes(const uint8_t* data, size_t size);

}  // namespace vaultstorm

#endif
