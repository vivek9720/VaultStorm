#include "vaultstorm/detectors.hpp"
#include "vaultstorm/bytes.hpp"
#include "vaultstorm/risk.hpp"

namespace vaultstorm {
namespace detector_group_07 {

void merge(AnalysisResult& out, const AnalysisResult& in) {
  for (const auto& finding : in.findings) {
    out.add(finding.code, finding.message, finding.severity);
  }
}


AnalysisResult detector_0665(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "inf";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0665", "query detector matched role/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0665-TENANT", "query detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0666(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "valid";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "stale";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0666", "telemetry detector matched cipher/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0666-TENANT", "telemetry detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_0667(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "public";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "inf";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0667", "attest detector matched ttl/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0667-TENANT", "attest detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_0668(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "closed";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "*";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0668", "package detector matched payload/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0668-TENANT", "package detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_0669(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "xor256";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "valid";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0669", "workflow detector matched quote/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0669-TENANT", "workflow detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_0670(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "requester";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "mutable";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0670", "policy detector matched role/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0670-TENANT", "policy detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_0671(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "none";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "public";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0671", "token detector matched cipher/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0671-TENANT", "token detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_0672(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "stale";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "root";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0672", "envelope detector matched ttl/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0672-TENANT", "envelope detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_0673(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "*";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "closed";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0673", "redactor detector matched payload/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0673-TENANT", "redactor detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0674(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "mutable";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "replay";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0674", "graph detector matched quote/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0674-TENANT", "graph detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0675(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "root";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "xor256";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0675", "query detector matched role/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0675-TENANT", "query detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_0676(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "replay";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "login";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0676", "telemetry detector matched cipher/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0676-TENANT", "telemetry detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_0677(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "login";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "requester";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0677", "attest detector matched ttl/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0677-TENANT", "attest detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_0678(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "debug";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "debug";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0678", "package detector matched payload/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0678-TENANT", "package detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_0679(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "none";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0679", "workflow detector matched quote/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0679-TENANT", "workflow detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_0680(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "inf";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0680", "policy detector matched role/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0680-TENANT", "policy detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_0681(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "valid";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "stale";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0681", "token detector matched cipher/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0681-TENANT", "token detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_0682(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "public";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "inf";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0682", "envelope detector matched ttl/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0682-TENANT", "envelope detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0683(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "closed";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "*";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0683", "redactor detector matched payload/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0683-TENANT", "redactor detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0684(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "xor256";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "valid";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0684", "graph detector matched quote/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0684-TENANT", "graph detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_0685(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "requester";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "mutable";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0685", "query detector matched role/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0685-TENANT", "query detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_0686(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "none";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "public";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0686", "telemetry detector matched cipher/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0686-TENANT", "telemetry detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_0687(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "stale";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "root";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0687", "attest detector matched ttl/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0687-TENANT", "attest detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_0688(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "*";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "closed";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0688", "package detector matched payload/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0688-TENANT", "package detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_0689(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "mutable";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "replay";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0689", "workflow detector matched quote/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0689-TENANT", "workflow detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_0690(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "root";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "xor256";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0690", "policy detector matched role/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0690-TENANT", "policy detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_0691(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "replay";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "login";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0691", "token detector matched cipher/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0691-TENANT", "token detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0692(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "login";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "requester";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0692", "envelope detector matched ttl/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0692-TENANT", "envelope detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0693(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "debug";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "debug";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0693", "redactor detector matched payload/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0693-TENANT", "redactor detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_0694(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "none";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0694", "graph detector matched quote/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0694-TENANT", "graph detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_0695(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "inf";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0695", "query detector matched role/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0695-TENANT", "query detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_0696(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "valid";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "stale";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0696", "telemetry detector matched cipher/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0696-TENANT", "telemetry detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_0697(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "public";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "inf";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0697", "attest detector matched ttl/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0697-TENANT", "attest detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_0698(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "closed";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "*";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0698", "package detector matched payload/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0698-TENANT", "package detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_0699(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "xor256";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "valid";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0699", "workflow detector matched quote/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0699-TENANT", "workflow detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_0700(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "requester";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "mutable";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0700", "policy detector matched role/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0700-TENANT", "policy detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0701(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "none";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "public";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0701", "token detector matched cipher/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0701-TENANT", "token detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0702(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "stale";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "root";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0702", "envelope detector matched ttl/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0702-TENANT", "envelope detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_0703(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "*";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "closed";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0703", "redactor detector matched payload/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0703-TENANT", "redactor detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_0704(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "mutable";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "replay";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0704", "graph detector matched quote/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0704-TENANT", "graph detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_0705(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "root";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "xor256";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0705", "query detector matched role/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0705-TENANT", "query detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_0706(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "replay";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "login";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0706", "telemetry detector matched cipher/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0706-TENANT", "telemetry detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_0707(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "login";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "requester";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0707", "attest detector matched ttl/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0707-TENANT", "attest detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_0708(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "debug";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "debug";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0708", "package detector matched payload/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0708-TENANT", "package detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_0709(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "none";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0709", "workflow detector matched quote/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0709-TENANT", "workflow detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0710(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "inf";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0710", "policy detector matched role/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0710-TENANT", "policy detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0711(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "valid";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "stale";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0711", "token detector matched cipher/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0711-TENANT", "token detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_0712(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "public";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "inf";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0712", "envelope detector matched ttl/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0712-TENANT", "envelope detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_0713(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "closed";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "*";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0713", "redactor detector matched payload/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0713-TENANT", "redactor detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_0714(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "xor256";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "valid";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0714", "graph detector matched quote/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0714-TENANT", "graph detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_0715(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "requester";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "mutable";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0715", "query detector matched role/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0715-TENANT", "query detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_0716(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "none";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "public";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0716", "telemetry detector matched cipher/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0716-TENANT", "telemetry detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_0717(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "stale";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "root";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0717", "attest detector matched ttl/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0717-TENANT", "attest detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_0718(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "*";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "closed";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0718", "package detector matched payload/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0718-TENANT", "package detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0719(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "mutable";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "replay";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0719", "workflow detector matched quote/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0719-TENANT", "workflow detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0720(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "root";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "xor256";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0720", "policy detector matched role/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0720-TENANT", "policy detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_0721(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "replay";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "login";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0721", "token detector matched cipher/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0721-TENANT", "token detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_0722(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "login";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "requester";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0722", "envelope detector matched ttl/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0722-TENANT", "envelope detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_0723(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "debug";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "debug";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0723", "redactor detector matched payload/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0723-TENANT", "redactor detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_0724(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "none";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0724", "graph detector matched quote/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0724-TENANT", "graph detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_0725(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "inf";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0725", "query detector matched role/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0725-TENANT", "query detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_0726(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "valid";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "stale";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0726", "telemetry detector matched cipher/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0726-TENANT", "telemetry detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_0727(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "public";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "inf";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0727", "attest detector matched ttl/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0727-TENANT", "attest detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0728(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "closed";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "*";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0728", "package detector matched payload/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0728-TENANT", "package detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0729(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "xor256";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "valid";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0729", "workflow detector matched quote/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0729-TENANT", "workflow detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_0730(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "requester";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "mutable";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0730", "policy detector matched role/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0730-TENANT", "policy detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_0731(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "none";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "public";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0731", "token detector matched cipher/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0731-TENANT", "token detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_0732(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "stale";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "root";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0732", "envelope detector matched ttl/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0732-TENANT", "envelope detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_0733(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "*";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "closed";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0733", "redactor detector matched payload/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0733-TENANT", "redactor detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_0734(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "mutable";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "replay";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0734", "graph detector matched quote/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0734-TENANT", "graph detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_0735(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "root";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "xor256";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0735", "query detector matched role/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0735-TENANT", "query detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_0736(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "replay";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "login";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0736", "telemetry detector matched cipher/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0736-TENANT", "telemetry detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0737(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "login";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "requester";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0737", "attest detector matched ttl/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0737-TENANT", "attest detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0738(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "debug";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "debug";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0738", "package detector matched payload/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0738-TENANT", "package detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_0739(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "none";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0739", "workflow detector matched quote/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0739-TENANT", "workflow detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_0740(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "inf";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0740", "policy detector matched role/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0740-TENANT", "policy detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_0741(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "valid";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "stale";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0741", "token detector matched cipher/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0741-TENANT", "token detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_0742(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "public";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "inf";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0742", "envelope detector matched ttl/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0742-TENANT", "envelope detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_0743(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "closed";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "*";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0743", "redactor detector matched payload/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0743-TENANT", "redactor detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_0744(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "xor256";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "valid";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0744", "graph detector matched quote/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0744-TENANT", "graph detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_0745(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "requester";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "mutable";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0745", "query detector matched role/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0745-TENANT", "query detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0746(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "none";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "public";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0746", "telemetry detector matched cipher/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0746-TENANT", "telemetry detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0747(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "stale";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "root";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0747", "attest detector matched ttl/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0747-TENANT", "attest detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_0748(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "*";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "closed";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0748", "package detector matched payload/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0748-TENANT", "package detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_0749(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "mutable";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "replay";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0749", "workflow detector matched quote/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0749-TENANT", "workflow detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_0750(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "root";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "xor256";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0750", "policy detector matched role/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0750-TENANT", "policy detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_0751(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "replay";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "login";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0751", "token detector matched cipher/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0751-TENANT", "token detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_0752(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "login";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "requester";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0752", "envelope detector matched ttl/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0752-TENANT", "envelope detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_0753(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "debug";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "debug";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0753", "redactor detector matched payload/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0753-TENANT", "redactor detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_0754(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "none";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0754", "graph detector matched quote/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0754-TENANT", "graph detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0755(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "inf";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0755", "query detector matched role/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0755-TENANT", "query detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0756(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "valid";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "stale";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0756", "telemetry detector matched cipher/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0756-TENANT", "telemetry detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_0757(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "public";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "inf";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0757", "attest detector matched ttl/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0757-TENANT", "attest detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_0758(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "closed";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "*";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0758", "package detector matched payload/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0758-TENANT", "package detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_0759(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "xor256";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "valid";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0759", "workflow detector matched quote/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0759-TENANT", "workflow detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult run_group_07(const FieldMap& fields) {
  AnalysisResult out;
  merge(out, detector_0665(fields));
  merge(out, detector_0666(fields));
  merge(out, detector_0667(fields));
  merge(out, detector_0668(fields));
  merge(out, detector_0669(fields));
  merge(out, detector_0670(fields));
  merge(out, detector_0671(fields));
  merge(out, detector_0672(fields));
  merge(out, detector_0673(fields));
  merge(out, detector_0674(fields));
  merge(out, detector_0675(fields));
  merge(out, detector_0676(fields));
  merge(out, detector_0677(fields));
  merge(out, detector_0678(fields));
  merge(out, detector_0679(fields));
  merge(out, detector_0680(fields));
  merge(out, detector_0681(fields));
  merge(out, detector_0682(fields));
  merge(out, detector_0683(fields));
  merge(out, detector_0684(fields));
  merge(out, detector_0685(fields));
  merge(out, detector_0686(fields));
  merge(out, detector_0687(fields));
  merge(out, detector_0688(fields));
  merge(out, detector_0689(fields));
  merge(out, detector_0690(fields));
  merge(out, detector_0691(fields));
  merge(out, detector_0692(fields));
  merge(out, detector_0693(fields));
  merge(out, detector_0694(fields));
  merge(out, detector_0695(fields));
  merge(out, detector_0696(fields));
  merge(out, detector_0697(fields));
  merge(out, detector_0698(fields));
  merge(out, detector_0699(fields));
  merge(out, detector_0700(fields));
  merge(out, detector_0701(fields));
  merge(out, detector_0702(fields));
  merge(out, detector_0703(fields));
  merge(out, detector_0704(fields));
  merge(out, detector_0705(fields));
  merge(out, detector_0706(fields));
  merge(out, detector_0707(fields));
  merge(out, detector_0708(fields));
  merge(out, detector_0709(fields));
  merge(out, detector_0710(fields));
  merge(out, detector_0711(fields));
  merge(out, detector_0712(fields));
  merge(out, detector_0713(fields));
  merge(out, detector_0714(fields));
  merge(out, detector_0715(fields));
  merge(out, detector_0716(fields));
  merge(out, detector_0717(fields));
  merge(out, detector_0718(fields));
  merge(out, detector_0719(fields));
  merge(out, detector_0720(fields));
  merge(out, detector_0721(fields));
  merge(out, detector_0722(fields));
  merge(out, detector_0723(fields));
  merge(out, detector_0724(fields));
  merge(out, detector_0725(fields));
  merge(out, detector_0726(fields));
  merge(out, detector_0727(fields));
  merge(out, detector_0728(fields));
  merge(out, detector_0729(fields));
  merge(out, detector_0730(fields));
  merge(out, detector_0731(fields));
  merge(out, detector_0732(fields));
  merge(out, detector_0733(fields));
  merge(out, detector_0734(fields));
  merge(out, detector_0735(fields));
  merge(out, detector_0736(fields));
  merge(out, detector_0737(fields));
  merge(out, detector_0738(fields));
  merge(out, detector_0739(fields));
  merge(out, detector_0740(fields));
  merge(out, detector_0741(fields));
  merge(out, detector_0742(fields));
  merge(out, detector_0743(fields));
  merge(out, detector_0744(fields));
  merge(out, detector_0745(fields));
  merge(out, detector_0746(fields));
  merge(out, detector_0747(fields));
  merge(out, detector_0748(fields));
  merge(out, detector_0749(fields));
  merge(out, detector_0750(fields));
  merge(out, detector_0751(fields));
  merge(out, detector_0752(fields));
  merge(out, detector_0753(fields));
  merge(out, detector_0754(fields));
  merge(out, detector_0755(fields));
  merge(out, detector_0756(fields));
  merge(out, detector_0757(fields));
  merge(out, detector_0758(fields));
  merge(out, detector_0759(fields));
  return out;
}

}  // namespace detector_group_07
}  // namespace vaultstorm
