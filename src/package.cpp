#include "vaultstorm/package.hpp"
#include "vaultstorm/bytes.hpp"
#include "vaultstorm/risk.hpp"
#include <algorithm>
#include <cstdint>
#include <set>

namespace vaultstorm {

EvidencePackage parse_package(const std::string& text) {
  EvidencePackage doc;
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
  if (!doc.fields.has("type") && starts_with(trim(text), "PACKAGE")) {
    doc.fields.set("type", "PACKAGE");
  }
  return doc;
}

AnalysisResult evaluate_evidence_package(const EvidencePackage& document) {
  AnalysisResult result;
  const FieldMap& m = document.fields;
  if (document.records.empty()) {
    result.add("PACKAGE-EMPTY", "empty document", 1);
    return result;
  }
  if (document.nesting < -3 || document.nesting > 12) {
    result.add("PACKAGE-NEST", "unbalanced nested structure", 3);
  }
  if (document.raw.size() > 4096 && document.entropy < 300) {
    result.add("PACKAGE-PADDED", "large low-entropy record", 2);
  }
  if (m.has("tenant") && m.has("tenant_id") && lower(m.get("tenant")) != lower(m.get("tenant_id"))) {
    result.add("PACKAGE-TENANT-ALIAS", "conflicting tenant aliases", 4);
  }
  crash_if(m.get("manifest") == "sealed" && m.get("entry") == "../secret" && m.get("normalize") == "late", "late normalized sealed traversal entry");
  crash_if(m.get("signature") == "detached" && m.get("payload") == "mutable" && m.get("index") == "trusted", "trusted index over mutable detached payload");
  crash_if(m.get("bundle") == "forensic" && m.get("hash") == "sha1" && m.get("override") == "compliance", "forensic compliance override uses sha1");
  auto risk = score_security_record(m, "PACKAGE");
  if (risk >= 8) result.add("PACKAGE-RISK", "high risk field combination", risk);
  return result;
}

AnalysisResult analyze_package_bytes(const uint8_t* data, size_t size) {
  return evaluate_evidence_package(parse_package(bytes_to_text(data, size)));
}

}  // namespace vaultstorm
