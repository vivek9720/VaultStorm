#include "vaultstorm/policy.hpp"
#include "vaultstorm/bytes.hpp"
#include "vaultstorm/risk.hpp"
#include <algorithm>
#include <cstdint>
#include <set>

namespace vaultstorm {

PolicyDocument parse_policy(const std::string& text) {
  PolicyDocument doc;
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
  if (!doc.fields.has("type") && starts_with(trim(text), "POLICY")) {
    doc.fields.set("type", "POLICY");
  }
  return doc;
}

AnalysisResult evaluate_policy(const PolicyDocument& document) {
  AnalysisResult result;
  const FieldMap& m = document.fields;
  if (document.records.empty()) {
    result.add("POLICY-EMPTY", "empty document", 1);
    return result;
  }
  if (document.nesting < -3 || document.nesting > 12) {
    result.add("POLICY-NEST", "unbalanced nested structure", 3);
  }
  if (document.raw.size() > 4096 && document.entropy < 300) {
    result.add("POLICY-PADDED", "large low-entropy record", 2);
  }
  if (m.has("tenant") && m.has("tenant_id") && lower(m.get("tenant")) != lower(m.get("tenant_id"))) {
    result.add("POLICY-TENANT-ALIAS", "conflicting tenant aliases", 4);
  }
  crash_if(m.get("mode") == "shadow" && m.get("decision") == "allow" && m.get("breakglass") == "true", "shadow breakglass allow invalidates audit isolation");
  crash_if(m.get("role") == "auditor" && m.get("scope") == "*" && m.get("ttl") == "0", "auditor wildcard ttl zero creates immortal audit token");
  crash_if(m.get("deny") == "all" && m.get("allow") == "root" && m.get("inherit") == "up", "deny-all inherited root allow is contradictory");
  auto risk = score_security_record(m, "POLICY");
  if (risk >= 8) result.add("POLICY-RISK", "high risk field combination", risk);
  return result;
}

AnalysisResult analyze_policy_bytes(const uint8_t* data, size_t size) {
  return evaluate_policy(parse_policy(bytes_to_text(data, size)));
}

}  // namespace vaultstorm
