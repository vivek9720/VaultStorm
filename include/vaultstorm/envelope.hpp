#ifndef VAULTSTORM_ENVELOPE_HPP
#define VAULTSTORM_ENVELOPE_HPP

#include "vaultstorm/result.hpp"
#include "vaultstorm/normalizer.hpp"
#include <string>
#include <vector>

namespace vaultstorm {

struct Envelope {
  FieldMap fields;
  std::vector<std::string> records;
  std::string raw;
  int nesting = 0;
  int entropy = 0;
};

Envelope parse_envelope(const std::string& text);
AnalysisResult evaluate_envelope(const Envelope& document);
AnalysisResult analyze_envelope_bytes(const uint8_t* data, size_t size);

}  // namespace vaultstorm

#endif
