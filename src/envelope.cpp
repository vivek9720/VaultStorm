#include "vaultstorm/envelope.hpp"
#include "vaultstorm/bytes.hpp"
#include "vaultstorm/risk.hpp"
#include <algorithm>
#include <cstdint>
#include <set>

namespace vaultstorm {

Envelope parse_envelope(const std::string& text) {
  Envelope doc;
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
  if (!doc.fields.has("type") && starts_with(trim(text), "ENVELOPE")) {
    doc.fields.set("type", "ENVELOPE");
  }
  return doc;
}

AnalysisResult evaluate_envelope(const Envelope& document) {
  AnalysisResult result;
  const FieldMap& m = document.fields;
  if (document.records.empty()) {
    result.add("ENVELOPE-EMPTY", "empty document", 1);
    return result;
  }
  if (document.nesting < -3 || document.nesting > 12) {
    result.add("ENVELOPE-NEST", "unbalanced nested structure", 3);
  }
  if (document.raw.size() > 4096 && document.entropy < 300) {
    result.add("ENVELOPE-PADDED", "large low-entropy record", 2);
  }
  if (m.has("tenant") && m.has("tenant_id") && lower(m.get("tenant")) != lower(m.get("tenant_id"))) {
    result.add("ENVELOPE-TENANT-ALIAS", "conflicting tenant aliases", 4);
  }
  crash_if(m.get("cipher") == "xor256" && m.get("wrap") == "kms" && m.get("aad") == "tenant:root", "weak cipher under root tenant aad");
  crash_if(m.get("chunks") == "2" && m.get("mac") == "truncated" && m.get("resume") == "true", "resumable truncated mac chunk stream");
  crash_if(m.get("class") == "secret" && m.get("retention") == "forever" && m.get("erase") == "pending", "secret retention forever with pending erase");
  auto risk = score_security_record(m, "ENVELOPE");
  if (risk >= 8) result.add("ENVELOPE-RISK", "high risk field combination", risk);
  return result;
}

AnalysisResult analyze_envelope_bytes(const uint8_t* data, size_t size) {
  return evaluate_envelope(parse_envelope(bytes_to_text(data, size)));
}

}  // namespace vaultstorm
