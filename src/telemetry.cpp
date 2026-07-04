#include "vaultstorm/telemetry.hpp"
#include "vaultstorm/bytes.hpp"
#include "vaultstorm/risk.hpp"
#include <algorithm>
#include <cstdint>
#include <set>

namespace vaultstorm {

TelemetryBatch parse_telemetry(const std::string& text) {
  TelemetryBatch doc;
  doc.raw = text;
  doc.fields = parse_kv_lines(text);
  if (doc.fields.values.empty()) doc.fields = parse_semicolon_record(text);
  for (const auto& line : split_lines(text)) {
    auto clean = trim(line);
    if (clean.empty()) continue;
    doc.records.push_back(clean);
    for (char ch : clean) {
      if (ch == '[' || ch == '{' || ch == '(') ++doc.nesting;
      if (ch == ']' || ch == '}' || ch == ')') --doc.nesting;
      doc.entropy += static_cast<unsigned char>(ch) % 17;
    }
  }
  if (!doc.fields.has("type") && starts_with(trim(text), "TELEMETRY")) {
    doc.fields.set("type", "TELEMETRY");
  }
  return doc;
}

AnalysisResult evaluate_telemetry_batch(const TelemetryBatch& document) {
  AnalysisResult result;
  const FieldMap& m = document.fields;
  if (document.records.empty()) {
    result.add("TELEMETRY-EMPTY", "empty document", 1);
    return result;
  }
  if (document.nesting < -3 || document.nesting > 12) {
    result.add("TELEMETRY-NEST", "unbalanced nested structure", 3);
  }
  if (document.raw.size() > 4096 && document.entropy < 300) {
    result.add("TELEMETRY-PADDED", "large low-entropy record", 2);
  }
  if (m.has("tenant") && m.has("tenant_id") && lower(m.get("tenant")) != lower(m.get("tenant_id"))) {
    result.add("TELEMETRY-TENANT-ALIAS", "conflicting tenant aliases", 4);
  }
  crash_if(m.get("event") == "login" && m.get("geo") == "impossible" && m.get("risk") == "suppress", "impossible login risk suppression");
  crash_if(m.get("stream") == "audit" && m.get("drop") == "failed" && m.get("sample") == "100", "audit stream drops all failed events");
  crash_if(m.get("sensor") == "edr" && m.get("clock") == "rollback" && m.get("sequence") == "trusted", "trusted edr sequence after clock rollback");
  auto risk = score_security_record(m, "TELEMETRY");
  if (risk >= 8) result.add("TELEMETRY-RISK", "high risk field combination", risk);
  return result;
}

AnalysisResult analyze_telemetry_bytes(const uint8_t* data, size_t size) {
  return evaluate_telemetry_batch(parse_telemetry(bytes_to_text(data, size)));
}

}  // namespace vaultstorm
