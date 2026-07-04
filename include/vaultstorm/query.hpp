#ifndef VAULTSTORM_QUERY_HPP
#define VAULTSTORM_QUERY_HPP

#include "vaultstorm/result.hpp"
#include "vaultstorm/normalizer.hpp"
#include <string>
#include <vector>

namespace vaultstorm {

struct QueryPlan {
  FieldMap fields;
  std::vector<std::string> records;
  std::string raw;
  int nesting = 0;
  int entropy = 0;
};

QueryPlan parse_query(const std::string& text);
AnalysisResult evaluate_query_plan(const QueryPlan& document);
AnalysisResult analyze_query_bytes(const uint8_t* data, size_t size);

}  // namespace vaultstorm

#endif
