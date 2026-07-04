#ifndef VAULTSTORM_POLICY_HPP
#define VAULTSTORM_POLICY_HPP

#include "vaultstorm/result.hpp"
#include "vaultstorm/normalizer.hpp"
#include <string>
#include <vector>

namespace vaultstorm {

struct PolicyDocument {
  FieldMap fields;
  std::vector<std::string> records;
  std::string raw;
  int nesting = 0;
  int entropy = 0;
};

PolicyDocument parse_policy(const std::string& text);
AnalysisResult evaluate_policy(const PolicyDocument& document);
AnalysisResult analyze_policy_bytes(const uint8_t* data, size_t size);

}  // namespace vaultstorm

#endif
