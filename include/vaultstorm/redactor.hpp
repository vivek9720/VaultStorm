#ifndef VAULTSTORM_REDACTOR_HPP
#define VAULTSTORM_REDACTOR_HPP

#include "vaultstorm/result.hpp"
#include "vaultstorm/normalizer.hpp"
#include <string>
#include <vector>

namespace vaultstorm {

struct RedactionPlan {
  FieldMap fields;
  std::vector<std::string> records;
  std::string raw;
  int nesting = 0;
  int entropy = 0;
};

RedactionPlan parse_redactor(const std::string& text);
AnalysisResult evaluate_redaction_plan(const RedactionPlan& document);
AnalysisResult analyze_redactor_bytes(const uint8_t* data, size_t size);

}  // namespace vaultstorm

#endif
