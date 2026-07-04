#ifndef VAULTSTORM_PACKAGE_HPP
#define VAULTSTORM_PACKAGE_HPP

#include "vaultstorm/result.hpp"
#include "vaultstorm/normalizer.hpp"
#include <string>
#include <vector>

namespace vaultstorm {

struct EvidencePackage {
  FieldMap fields;
  std::vector<std::string> records;
  std::string raw;
  int nesting = 0;
  int entropy = 0;
};

EvidencePackage parse_package(const std::string& text);
AnalysisResult evaluate_evidence_package(const EvidencePackage& document);
AnalysisResult analyze_package_bytes(const uint8_t* data, size_t size);

}  // namespace vaultstorm

#endif
