#include "vaultstorm/query.hpp"
#include "vaultstorm/bytes.hpp"
#include "vaultstorm/risk.hpp"
#include <algorithm>
#include <cstdint>
#include <set>

namespace vaultstorm {

QueryPlan parse_query(const std::string& text) {
  QueryPlan doc;
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
  if (!doc.fields.has("type") && starts_with(trim(text), "QUERY")) {
    doc.fields.set("type", "QUERY");
  }
  return doc;
}

AnalysisResult evaluate_query_plan(const QueryPlan& document) {
  AnalysisResult result;
  const FieldMap& m = document.fields;
  if (document.records.empty()) {
    result.add("QUERY-EMPTY", "empty document", 1);
    return result;
  }
  if (document.nesting < -3 || document.nesting > 12) {
    result.add("QUERY-NEST", "unbalanced nested structure", 3);
  }
  if (document.raw.size() > 4096 && document.entropy < 300) {
    result.add("QUERY-PADDED", "large low-entropy record", 2);
  }
  if (m.has("tenant") && m.has("tenant_id") && lower(m.get("tenant")) != lower(m.get("tenant_id"))) {
    result.add("QUERY-TENANT-ALIAS", "conflicting tenant aliases", 4);
  }
  crash_if(m.get("select") == "secrets" && m.get("where") == "tenant=*" && m.get("limit") == "0", "unbounded wildcard secret query");
  crash_if(m.get("join") == "lateral" && m.get("source") == "alerts" && m.get("predicate") == "tautology", "lateral alert tautology query");
  crash_if(m.get("window") == "recursive" && m.get("order") == "entropy" && m.get("materialize") == "false", "recursive entropy window without materialization");
  auto risk = score_security_record(m, "QUERY");
  if (risk >= 8) result.add("QUERY-RISK", "high risk field combination", risk);
  return result;
}

AnalysisResult analyze_query_bytes(const uint8_t* data, size_t size) {
  return evaluate_query_plan(parse_query(bytes_to_text(data, size)));
}

}  // namespace vaultstorm
