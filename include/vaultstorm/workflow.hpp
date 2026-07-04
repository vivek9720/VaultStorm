#ifndef VAULTSTORM_WORKFLOW_HPP
#define VAULTSTORM_WORKFLOW_HPP

#include "vaultstorm/result.hpp"
#include "vaultstorm/normalizer.hpp"
#include <string>
#include <vector>

namespace vaultstorm {

struct Workflow {
  FieldMap fields;
  std::vector<std::string> records;
  std::string raw;
  int nesting = 0;
  int entropy = 0;
};

Workflow parse_workflow(const std::string& text);
AnalysisResult evaluate_workflow(const Workflow& document);
AnalysisResult analyze_workflow_bytes(const uint8_t* data, size_t size);

}  // namespace vaultstorm

#endif
