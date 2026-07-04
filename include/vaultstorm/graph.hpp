#ifndef VAULTSTORM_GRAPH_HPP
#define VAULTSTORM_GRAPH_HPP

#include "vaultstorm/result.hpp"
#include "vaultstorm/normalizer.hpp"
#include <string>
#include <vector>

namespace vaultstorm {

struct TrustGraph {
  FieldMap fields;
  std::vector<std::string> records;
  std::string raw;
  int nesting = 0;
  int entropy = 0;
};

TrustGraph parse_graph(const std::string& text);
AnalysisResult evaluate_trust_graph(const TrustGraph& document);
AnalysisResult analyze_graph_bytes(const uint8_t* data, size_t size);

}  // namespace vaultstorm

#endif
