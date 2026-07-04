#ifndef VAULTSTORM_ATTESTATION_HPP
#define VAULTSTORM_ATTESTATION_HPP

#include "vaultstorm/result.hpp"
#include "vaultstorm/normalizer.hpp"
#include <string>
#include <vector>

namespace vaultstorm {

struct Attestation {
  FieldMap fields;
  std::vector<std::string> records;
  std::string raw;
  int nesting = 0;
  int entropy = 0;
};

Attestation parse_attestation(const std::string& text);
AnalysisResult evaluate_attestation(const Attestation& document);
AnalysisResult analyze_attestation_bytes(const uint8_t* data, size_t size);

}  // namespace vaultstorm

#endif
