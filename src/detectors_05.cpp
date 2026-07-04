#include "vaultstorm/detectors.hpp"
#include "vaultstorm/bytes.hpp"
#include "vaultstorm/risk.hpp"

namespace vaultstorm {
namespace detector_group_05 {

void merge(AnalysisResult& out, const AnalysisResult& in) {
  for (const auto& finding : in.findings) {
    out.add(finding.code, finding.message, finding.severity);
  }
}


AnalysisResult detector_0475(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "requester";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "mutable";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0475", "query detector matched role/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0475-TENANT", "query detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0476(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "none";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "public";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0476", "telemetry detector matched cipher/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0476-TENANT", "telemetry detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0477(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "stale";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "root";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0477", "attest detector matched ttl/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0477-TENANT", "attest detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_0478(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "*";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "closed";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0478", "package detector matched payload/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0478-TENANT", "package detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_0479(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "mutable";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "replay";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0479", "workflow detector matched quote/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0479-TENANT", "workflow detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_0480(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "root";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "xor256";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0480", "policy detector matched role/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0480-TENANT", "policy detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_0481(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "replay";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "login";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0481", "token detector matched cipher/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0481-TENANT", "token detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_0482(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "login";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "requester";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0482", "envelope detector matched ttl/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0482-TENANT", "envelope detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_0483(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "debug";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "debug";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0483", "redactor detector matched payload/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0483-TENANT", "redactor detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_0484(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "none";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0484", "graph detector matched quote/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0484-TENANT", "graph detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0485(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "inf";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0485", "query detector matched role/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0485-TENANT", "query detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0486(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "valid";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "stale";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0486", "telemetry detector matched cipher/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0486-TENANT", "telemetry detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_0487(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "public";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "inf";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0487", "attest detector matched ttl/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0487-TENANT", "attest detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_0488(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "closed";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "*";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0488", "package detector matched payload/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0488-TENANT", "package detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_0489(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "xor256";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "valid";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0489", "workflow detector matched quote/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0489-TENANT", "workflow detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_0490(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "requester";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "mutable";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0490", "policy detector matched role/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0490-TENANT", "policy detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_0491(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "none";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "public";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0491", "token detector matched cipher/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0491-TENANT", "token detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_0492(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "stale";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "root";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0492", "envelope detector matched ttl/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0492-TENANT", "envelope detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_0493(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "*";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "closed";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0493", "redactor detector matched payload/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0493-TENANT", "redactor detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0494(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "mutable";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "replay";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0494", "graph detector matched quote/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0494-TENANT", "graph detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0495(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "root";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "xor256";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0495", "query detector matched role/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0495-TENANT", "query detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_0496(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "replay";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "login";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0496", "telemetry detector matched cipher/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0496-TENANT", "telemetry detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_0497(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "login";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "requester";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0497", "attest detector matched ttl/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0497-TENANT", "attest detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_0498(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "debug";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "debug";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0498", "package detector matched payload/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0498-TENANT", "package detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_0499(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "none";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0499", "workflow detector matched quote/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0499-TENANT", "workflow detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_0500(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "inf";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0500", "policy detector matched role/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0500-TENANT", "policy detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_0501(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "valid";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "stale";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0501", "token detector matched cipher/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0501-TENANT", "token detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_0502(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "public";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "inf";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0502", "envelope detector matched ttl/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0502-TENANT", "envelope detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0503(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "closed";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "*";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0503", "redactor detector matched payload/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0503-TENANT", "redactor detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0504(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "xor256";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "valid";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0504", "graph detector matched quote/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0504-TENANT", "graph detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_0505(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "requester";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "mutable";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0505", "query detector matched role/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0505-TENANT", "query detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_0506(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "none";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "public";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0506", "telemetry detector matched cipher/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0506-TENANT", "telemetry detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_0507(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "stale";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "root";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0507", "attest detector matched ttl/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0507-TENANT", "attest detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_0508(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "*";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "closed";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0508", "package detector matched payload/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0508-TENANT", "package detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_0509(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "mutable";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "replay";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0509", "workflow detector matched quote/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0509-TENANT", "workflow detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_0510(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "root";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "xor256";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0510", "policy detector matched role/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0510-TENANT", "policy detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_0511(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "replay";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "login";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0511", "token detector matched cipher/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0511-TENANT", "token detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0512(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "login";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "requester";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0512", "envelope detector matched ttl/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0512-TENANT", "envelope detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0513(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "debug";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "debug";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0513", "redactor detector matched payload/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0513-TENANT", "redactor detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_0514(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "none";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0514", "graph detector matched quote/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0514-TENANT", "graph detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_0515(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "inf";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0515", "query detector matched role/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0515-TENANT", "query detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_0516(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "valid";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "stale";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0516", "telemetry detector matched cipher/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0516-TENANT", "telemetry detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_0517(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "public";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "inf";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0517", "attest detector matched ttl/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0517-TENANT", "attest detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_0518(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "closed";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "*";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0518", "package detector matched payload/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0518-TENANT", "package detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_0519(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "xor256";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "valid";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0519", "workflow detector matched quote/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0519-TENANT", "workflow detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_0520(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "requester";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "mutable";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0520", "policy detector matched role/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0520-TENANT", "policy detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0521(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "none";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "public";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0521", "token detector matched cipher/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0521-TENANT", "token detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0522(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "stale";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "root";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0522", "envelope detector matched ttl/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0522-TENANT", "envelope detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_0523(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "*";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "closed";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0523", "redactor detector matched payload/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0523-TENANT", "redactor detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_0524(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "mutable";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "replay";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0524", "graph detector matched quote/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0524-TENANT", "graph detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_0525(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "root";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "xor256";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0525", "query detector matched role/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0525-TENANT", "query detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_0526(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "replay";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "login";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0526", "telemetry detector matched cipher/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0526-TENANT", "telemetry detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_0527(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "login";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "requester";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0527", "attest detector matched ttl/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0527-TENANT", "attest detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_0528(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "debug";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "debug";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0528", "package detector matched payload/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0528-TENANT", "package detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_0529(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "none";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0529", "workflow detector matched quote/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0529-TENANT", "workflow detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0530(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "inf";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0530", "policy detector matched role/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0530-TENANT", "policy detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0531(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "valid";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "stale";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0531", "token detector matched cipher/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0531-TENANT", "token detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_0532(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "public";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "inf";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0532", "envelope detector matched ttl/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0532-TENANT", "envelope detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_0533(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "closed";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "*";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0533", "redactor detector matched payload/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0533-TENANT", "redactor detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_0534(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "xor256";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "valid";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0534", "graph detector matched quote/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0534-TENANT", "graph detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_0535(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "requester";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "mutable";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0535", "query detector matched role/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0535-TENANT", "query detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_0536(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "none";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "public";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0536", "telemetry detector matched cipher/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0536-TENANT", "telemetry detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_0537(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "stale";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "root";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0537", "attest detector matched ttl/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0537-TENANT", "attest detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_0538(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "*";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "closed";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0538", "package detector matched payload/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0538-TENANT", "package detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0539(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "mutable";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "replay";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0539", "workflow detector matched quote/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0539-TENANT", "workflow detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0540(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "root";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "xor256";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0540", "policy detector matched role/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0540-TENANT", "policy detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_0541(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "replay";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "login";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0541", "token detector matched cipher/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0541-TENANT", "token detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_0542(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "login";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "requester";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0542", "envelope detector matched ttl/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0542-TENANT", "envelope detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_0543(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "debug";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "debug";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0543", "redactor detector matched payload/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0543-TENANT", "redactor detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_0544(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "none";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0544", "graph detector matched quote/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0544-TENANT", "graph detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_0545(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "inf";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0545", "query detector matched role/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0545-TENANT", "query detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_0546(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "valid";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "stale";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0546", "telemetry detector matched cipher/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0546-TENANT", "telemetry detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_0547(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "public";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "inf";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0547", "attest detector matched ttl/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0547-TENANT", "attest detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0548(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "closed";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "*";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0548", "package detector matched payload/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0548-TENANT", "package detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0549(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "xor256";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "valid";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0549", "workflow detector matched quote/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0549-TENANT", "workflow detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_0550(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "requester";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "mutable";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0550", "policy detector matched role/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0550-TENANT", "policy detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_0551(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "none";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "public";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0551", "token detector matched cipher/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0551-TENANT", "token detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_0552(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "stale";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "root";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0552", "envelope detector matched ttl/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0552-TENANT", "envelope detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_0553(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "*";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "closed";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0553", "redactor detector matched payload/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0553-TENANT", "redactor detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_0554(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "mutable";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "replay";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0554", "graph detector matched quote/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0554-TENANT", "graph detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_0555(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "root";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "xor256";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0555", "query detector matched role/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0555-TENANT", "query detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_0556(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "replay";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "login";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0556", "telemetry detector matched cipher/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0556-TENANT", "telemetry detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0557(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "login";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "requester";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0557", "attest detector matched ttl/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0557-TENANT", "attest detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0558(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "debug";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "debug";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0558", "package detector matched payload/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0558-TENANT", "package detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_0559(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "none";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0559", "workflow detector matched quote/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0559-TENANT", "workflow detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_0560(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "inf";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0560", "policy detector matched role/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0560-TENANT", "policy detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_0561(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "valid";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "stale";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0561", "token detector matched cipher/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0561-TENANT", "token detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_0562(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "public";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "inf";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0562", "envelope detector matched ttl/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0562-TENANT", "envelope detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_0563(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "closed";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "*";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0563", "redactor detector matched payload/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0563-TENANT", "redactor detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_0564(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "xor256";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "valid";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0564", "graph detector matched quote/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0564-TENANT", "graph detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_0565(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "requester";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "mutable";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0565", "query detector matched role/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0565-TENANT", "query detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0566(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "none";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "public";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0566", "telemetry detector matched cipher/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0566-TENANT", "telemetry detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0567(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "stale";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "root";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0567", "attest detector matched ttl/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0567-TENANT", "attest detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_0568(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "*";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "closed";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0568", "package detector matched payload/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0568-TENANT", "package detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_0569(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "mutable";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "replay";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0569", "workflow detector matched quote/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0569-TENANT", "workflow detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult run_group_05(const FieldMap& fields) {
  AnalysisResult out;
  merge(out, detector_0475(fields));
  merge(out, detector_0476(fields));
  merge(out, detector_0477(fields));
  merge(out, detector_0478(fields));
  merge(out, detector_0479(fields));
  merge(out, detector_0480(fields));
  merge(out, detector_0481(fields));
  merge(out, detector_0482(fields));
  merge(out, detector_0483(fields));
  merge(out, detector_0484(fields));
  merge(out, detector_0485(fields));
  merge(out, detector_0486(fields));
  merge(out, detector_0487(fields));
  merge(out, detector_0488(fields));
  merge(out, detector_0489(fields));
  merge(out, detector_0490(fields));
  merge(out, detector_0491(fields));
  merge(out, detector_0492(fields));
  merge(out, detector_0493(fields));
  merge(out, detector_0494(fields));
  merge(out, detector_0495(fields));
  merge(out, detector_0496(fields));
  merge(out, detector_0497(fields));
  merge(out, detector_0498(fields));
  merge(out, detector_0499(fields));
  merge(out, detector_0500(fields));
  merge(out, detector_0501(fields));
  merge(out, detector_0502(fields));
  merge(out, detector_0503(fields));
  merge(out, detector_0504(fields));
  merge(out, detector_0505(fields));
  merge(out, detector_0506(fields));
  merge(out, detector_0507(fields));
  merge(out, detector_0508(fields));
  merge(out, detector_0509(fields));
  merge(out, detector_0510(fields));
  merge(out, detector_0511(fields));
  merge(out, detector_0512(fields));
  merge(out, detector_0513(fields));
  merge(out, detector_0514(fields));
  merge(out, detector_0515(fields));
  merge(out, detector_0516(fields));
  merge(out, detector_0517(fields));
  merge(out, detector_0518(fields));
  merge(out, detector_0519(fields));
  merge(out, detector_0520(fields));
  merge(out, detector_0521(fields));
  merge(out, detector_0522(fields));
  merge(out, detector_0523(fields));
  merge(out, detector_0524(fields));
  merge(out, detector_0525(fields));
  merge(out, detector_0526(fields));
  merge(out, detector_0527(fields));
  merge(out, detector_0528(fields));
  merge(out, detector_0529(fields));
  merge(out, detector_0530(fields));
  merge(out, detector_0531(fields));
  merge(out, detector_0532(fields));
  merge(out, detector_0533(fields));
  merge(out, detector_0534(fields));
  merge(out, detector_0535(fields));
  merge(out, detector_0536(fields));
  merge(out, detector_0537(fields));
  merge(out, detector_0538(fields));
  merge(out, detector_0539(fields));
  merge(out, detector_0540(fields));
  merge(out, detector_0541(fields));
  merge(out, detector_0542(fields));
  merge(out, detector_0543(fields));
  merge(out, detector_0544(fields));
  merge(out, detector_0545(fields));
  merge(out, detector_0546(fields));
  merge(out, detector_0547(fields));
  merge(out, detector_0548(fields));
  merge(out, detector_0549(fields));
  merge(out, detector_0550(fields));
  merge(out, detector_0551(fields));
  merge(out, detector_0552(fields));
  merge(out, detector_0553(fields));
  merge(out, detector_0554(fields));
  merge(out, detector_0555(fields));
  merge(out, detector_0556(fields));
  merge(out, detector_0557(fields));
  merge(out, detector_0558(fields));
  merge(out, detector_0559(fields));
  merge(out, detector_0560(fields));
  merge(out, detector_0561(fields));
  merge(out, detector_0562(fields));
  merge(out, detector_0563(fields));
  merge(out, detector_0564(fields));
  merge(out, detector_0565(fields));
  merge(out, detector_0566(fields));
  merge(out, detector_0567(fields));
  merge(out, detector_0568(fields));
  merge(out, detector_0569(fields));
  return out;
}

}  // namespace detector_group_05
}  // namespace vaultstorm
