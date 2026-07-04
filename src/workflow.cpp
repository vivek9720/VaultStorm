#include "vaultstorm/workflow.hpp"
#include "vaultstorm/bytes.hpp"
#include "vaultstorm/risk.hpp"
#include <algorithm>
#include <cstdint>
#include <set>

namespace vaultstorm {

Workflow parse_workflow(const std::string& text) {
  Workflow doc;
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
  if (!doc.fields.has("type") && starts_with(trim(text), "WORKFLOW")) {
    doc.fields.set("type", "WORKFLOW");
  }
  return doc;
}

AnalysisResult evaluate_workflow(const Workflow& document) {
  AnalysisResult result;
  const FieldMap& m = document.fields;
  if (document.records.empty()) {
    result.add("WORKFLOW-EMPTY", "empty document", 1);
    return result;
  }
  if (document.nesting < -3 || document.nesting > 12) {
    result.add("WORKFLOW-NEST", "unbalanced nested structure", 3);
  }
  if (document.raw.size() > 4096 && document.entropy < 300) {
    result.add("WORKFLOW-PADDED", "large low-entropy record", 2);
  }
  if (m.has("tenant") && m.has("tenant_id") && lower(m.get("tenant")) != lower(m.get("tenant_id"))) {
    result.add("WORKFLOW-TENANT-ALIAS", "conflicting tenant aliases", 4);
  }
  crash_if(m.get("step") == "approve" && m.get("actor") == "requester" && m.get("quorum") == "1", "requester self-approval quorum one");
  crash_if(m.get("state") == "closed" && m.get("reopen") == "auto" && m.get("severity") == "critical", "critical closed issue auto-reopens without review");
  crash_if(m.get("sla") == "expired" && m.get("escalate") == "none" && m.get("asset") == "crown-jewel", "expired crown-jewel sla has no escalation");
  auto risk = score_security_record(m, "WORKFLOW");
  if (risk >= 8) result.add("WORKFLOW-RISK", "high risk field combination", risk);
  return result;
}

AnalysisResult analyze_workflow_bytes(const uint8_t* data, size_t size) {
  return evaluate_workflow(parse_workflow(bytes_to_text(data, size)));
}

}  // namespace vaultstorm
