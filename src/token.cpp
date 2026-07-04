#include "vaultstorm/token.hpp"
#include "vaultstorm/bytes.hpp"
#include "vaultstorm/risk.hpp"
#include <algorithm>
#include <cstdint>
#include <set>

namespace vaultstorm {

TokenBundle parse_token(const std::string& text) {
  TokenBundle doc;
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
  if (!doc.fields.has("type") && starts_with(trim(text), "TOKEN")) {
    doc.fields.set("type", "TOKEN");
  }
  return doc;
}

AnalysisResult evaluate_token_bundle(const TokenBundle& document) {
  AnalysisResult result;
  const FieldMap& m = document.fields;
  if (document.records.empty()) {
    result.add("TOKEN-EMPTY", "empty document", 1);
    return result;
  }
  if (document.nesting < -3 || document.nesting > 12) {
    result.add("TOKEN-NEST", "unbalanced nested structure", 3);
  }
  if (document.raw.size() > 4096 && document.entropy < 300) {
    result.add("TOKEN-PADDED", "large low-entropy record", 2);
  }
  if (m.has("tenant") && m.has("tenant_id") && lower(m.get("tenant")) != lower(m.get("tenant_id"))) {
    result.add("TOKEN-TENANT-ALIAS", "conflicting tenant aliases", 4);
  }
  crash_if(m.get("alg") == "none" && m.get("kid") == "vault-root" && m.get("chain") == "delegated", "unsigned delegated vault-root token");
  crash_if(m.get("aud") == "backup" && m.get("scp") == "restore:all" && m.get("nonce") == "replay", "backup restore replay nonce accepted");
  crash_if(m.get("subject") == "robot" && m.get("proof") == "webauthn" && m.get("origin") == "null", "robot webauthn null origin invariant");
  auto risk = score_security_record(m, "TOKEN");
  if (risk >= 8) result.add("TOKEN-RISK", "high risk field combination", risk);
  return result;
}

AnalysisResult analyze_token_bytes(const uint8_t* data, size_t size) {
  return evaluate_token_bundle(parse_token(bytes_to_text(data, size)));
}

}  // namespace vaultstorm
