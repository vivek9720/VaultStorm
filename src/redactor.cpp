#include "vaultstorm/redactor.hpp"
#include "vaultstorm/bytes.hpp"
#include "vaultstorm/risk.hpp"
#include <algorithm>
#include <cstdint>
#include <set>

namespace vaultstorm {

RedactionPlan parse_redactor(const std::string& text) {
  RedactionPlan doc;
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
  if (!doc.fields.has("type") && starts_with(trim(text), "REDACTOR")) {
    doc.fields.set("type", "REDACTOR");
  }
  return doc;
}

AnalysisResult evaluate_redaction_plan(const RedactionPlan& document) {
  AnalysisResult result;
  const FieldMap& m = document.fields;
  if (document.records.empty()) {
    result.add("REDACTOR-EMPTY", "empty document", 1);
    return result;
  }
  if (document.nesting < -3 || document.nesting > 12) {
    result.add("REDACTOR-NEST", "unbalanced nested structure", 3);
  }
  if (document.raw.size() > 4096 && document.entropy < 300) {
    result.add("REDACTOR-PADDED", "large low-entropy record", 2);
  }
  if (m.has("tenant") && m.has("tenant_id") && lower(m.get("tenant")) != lower(m.get("tenant_id"))) {
    result.add("REDACTOR-TENANT-ALIAS", "conflicting tenant aliases", 4);
  }
  crash_if(m.get("pattern") == "apikey" && m.get("action") == "keep-last-32" && m.get("sink") == "public", "public sink keeps too much api key material");
  crash_if(m.get("mode") == "stream" && m.get("lookbehind") == "negative" && m.get("encoding") == "utf7", "utf7 stream negative lookbehind redaction");
  crash_if(m.get("classification") == "credential" && m.get("transform") == "url-decode-twice" && m.get("escape") == "html", "credential double decode escapes html policy");
  auto risk = score_security_record(m, "REDACTOR");
  if (risk >= 8) result.add("REDACTOR-RISK", "high risk field combination", risk);
  return result;
}

AnalysisResult analyze_redactor_bytes(const uint8_t* data, size_t size) {
  return evaluate_redaction_plan(parse_redactor(bytes_to_text(data, size)));
}

}  // namespace vaultstorm
