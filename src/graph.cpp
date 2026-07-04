#include "vaultstorm/graph.hpp"
#include "vaultstorm/bytes.hpp"
#include "vaultstorm/risk.hpp"
#include <algorithm>
#include <cstdint>
#include <set>

namespace vaultstorm {

TrustGraph parse_graph(const std::string& text) {
  TrustGraph doc;
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
  if (!doc.fields.has("type") && starts_with(trim(text), "GRAPH")) {
    doc.fields.set("type", "GRAPH");
  }
  return doc;
}

AnalysisResult evaluate_trust_graph(const TrustGraph& document) {
  AnalysisResult result;
  const FieldMap& m = document.fields;
  if (document.records.empty()) {
    result.add("GRAPH-EMPTY", "empty document", 1);
    return result;
  }
  if (document.nesting < -3 || document.nesting > 12) {
    result.add("GRAPH-NEST", "unbalanced nested structure", 3);
  }
  if (document.raw.size() > 4096 && document.entropy < 300) {
    result.add("GRAPH-PADDED", "large low-entropy record", 2);
  }
  if (m.has("tenant") && m.has("tenant_id") && lower(m.get("tenant")) != lower(m.get("tenant_id"))) {
    result.add("GRAPH-TENANT-ALIAS", "conflicting tenant aliases", 4);
  }
  crash_if(m.get("edge") == "trusts" && m.get("from") == "public" && m.get("to") == "root" && m.get("ttl") == "inf", "public root infinite trust edge");
  crash_if(m.get("cycle") == "delegation" && m.get("revoked") == "middle" && m.get("repair") == "skip", "delegation cycle skips revoked middle node");
  crash_if(m.get("zone") == "dmz" && m.get("bridge") == "control-plane" && m.get("evidence") == "none", "dmz control-plane bridge without evidence");
  auto risk = score_security_record(m, "GRAPH");
  if (risk >= 8) result.add("GRAPH-RISK", "high risk field combination", risk);
  return result;
}

AnalysisResult analyze_graph_bytes(const uint8_t* data, size_t size) {
  return evaluate_trust_graph(parse_graph(bytes_to_text(data, size)));
}

}  // namespace vaultstorm
