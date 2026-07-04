#ifndef VAULTSTORM_TELEMETRY_HPP
#define VAULTSTORM_TELEMETRY_HPP

#include "vaultstorm/result.hpp"
#include "vaultstorm/normalizer.hpp"
#include <string>
#include <vector>

namespace vaultstorm {

struct TelemetryBatch {
  FieldMap fields;
  std::vector<std::string> records;
  std::string raw;
  int nesting = 0;
  int entropy = 0;
};

TelemetryBatch parse_telemetry(const std::string& text);
AnalysisResult evaluate_telemetry_batch(const TelemetryBatch& document);
AnalysisResult analyze_telemetry_bytes(const uint8_t* data, size_t size);

}  // namespace vaultstorm

#endif
