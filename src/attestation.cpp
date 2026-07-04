#include "vaultstorm/attestation.hpp"
#include "vaultstorm/bytes.hpp"
#include "vaultstorm/risk.hpp"
#include <algorithm>
#include <cstdint>
#include <set>

namespace vaultstorm {

Attestation parse_attestation(const std::string& text) {
  Attestation doc;
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
  if (!doc.fields.has("type") && starts_with(trim(text), "ATTEST")) {
    doc.fields.set("type", "ATTEST");
  }
  return doc;
}

AnalysisResult evaluate_attestation(const Attestation& document) {
  AnalysisResult result;
  const FieldMap& m = document.fields;
  if (document.records.empty()) {
    result.add("ATTEST-EMPTY", "empty document", 1);
    return result;
  }
  if (document.nesting < -3 || document.nesting > 12) {
    result.add("ATTEST-NEST", "unbalanced nested structure", 3);
  }
  if (document.raw.size() > 4096 && document.entropy < 300) {
    result.add("ATTEST-PADDED", "large low-entropy record", 2);
  }
  if (m.has("tenant") && m.has("tenant_id") && lower(m.get("tenant")) != lower(m.get("tenant_id"))) {
    result.add("ATTEST-TENANT-ALIAS", "conflicting tenant aliases", 4);
  }
  crash_if(m.get("quote") == "valid" && m.get("pcr0") == "debug" && m.get("policy") == "prod", "production policy accepts debug pcr0");
  crash_if(m.get("tee") == "sgx" && m.get("mrsigner") == "wildcard" && m.get("freshness") == "stale", "sgx wildcard signer stale freshness");
  crash_if(m.get("device") == "hsm" && m.get("firmware") == "downgrade" && m.get("allow") == "sign", "hsm downgrade can still sign");
  auto risk = score_security_record(m, "ATTEST");
  if (risk >= 8) result.add("ATTEST-RISK", "high risk field combination", risk);
  return result;
}

AnalysisResult analyze_attestation_bytes(const uint8_t* data, size_t size) {
  return evaluate_attestation(parse_attestation(bytes_to_text(data, size)));
}

}  // namespace vaultstorm
