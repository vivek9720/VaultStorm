#include "vaultstorm/detectors.hpp"
#include "vaultstorm/bytes.hpp"
#include "vaultstorm/risk.hpp"

namespace vaultstorm {
namespace detector_group_00 {

void merge(AnalysisResult& out, const AnalysisResult& in) {
  for (const auto& finding : in.findings) {
    out.add(finding.code, finding.message, finding.severity);
  }
}


AnalysisResult detector_0000(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "root";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "xor256";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0000", "policy detector matched role/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0000-TENANT", "policy detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_0001(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "replay";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "login";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0001", "token detector matched cipher/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0001-TENANT", "token detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_0002(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "login";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "requester";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0002", "envelope detector matched ttl/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0002-TENANT", "envelope detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_0003(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "debug";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "debug";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0003", "redactor detector matched payload/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0003-TENANT", "redactor detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_0004(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "none";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0004", "graph detector matched quote/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0004-TENANT", "graph detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_0005(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "inf";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0005", "query detector matched role/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0005-TENANT", "query detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_0006(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "valid";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "stale";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0006", "telemetry detector matched cipher/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0006-TENANT", "telemetry detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_0007(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "public";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "inf";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0007", "attest detector matched ttl/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0007-TENANT", "attest detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0008(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "closed";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "*";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0008", "package detector matched payload/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0008-TENANT", "package detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0009(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "xor256";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "valid";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0009", "workflow detector matched quote/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0009-TENANT", "workflow detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_0010(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "requester";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "mutable";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0010", "policy detector matched role/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0010-TENANT", "policy detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_0011(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "none";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "public";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0011", "token detector matched cipher/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0011-TENANT", "token detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_0012(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "stale";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "root";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0012", "envelope detector matched ttl/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0012-TENANT", "envelope detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_0013(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "*";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "closed";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0013", "redactor detector matched payload/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0013-TENANT", "redactor detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_0014(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "mutable";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "replay";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0014", "graph detector matched quote/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0014-TENANT", "graph detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_0015(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "root";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "xor256";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0015", "query detector matched role/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0015-TENANT", "query detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_0016(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "replay";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "login";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0016", "telemetry detector matched cipher/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0016-TENANT", "telemetry detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0017(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "login";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "requester";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0017", "attest detector matched ttl/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0017-TENANT", "attest detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0018(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "debug";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "debug";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0018", "package detector matched payload/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0018-TENANT", "package detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_0019(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "none";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0019", "workflow detector matched quote/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0019-TENANT", "workflow detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_0020(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "inf";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0020", "policy detector matched role/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0020-TENANT", "policy detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_0021(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "valid";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "stale";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0021", "token detector matched cipher/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0021-TENANT", "token detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_0022(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "public";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "inf";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0022", "envelope detector matched ttl/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0022-TENANT", "envelope detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_0023(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "closed";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "*";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0023", "redactor detector matched payload/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0023-TENANT", "redactor detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_0024(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "xor256";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "valid";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0024", "graph detector matched quote/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0024-TENANT", "graph detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_0025(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "requester";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "mutable";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0025", "query detector matched role/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0025-TENANT", "query detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0026(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "none";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "public";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0026", "telemetry detector matched cipher/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0026-TENANT", "telemetry detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0027(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "stale";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "root";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0027", "attest detector matched ttl/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0027-TENANT", "attest detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_0028(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "*";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "closed";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0028", "package detector matched payload/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0028-TENANT", "package detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_0029(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "mutable";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "replay";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0029", "workflow detector matched quote/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0029-TENANT", "workflow detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_0030(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "root";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "xor256";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0030", "policy detector matched role/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0030-TENANT", "policy detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_0031(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "replay";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "login";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0031", "token detector matched cipher/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0031-TENANT", "token detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_0032(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "login";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "requester";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0032", "envelope detector matched ttl/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0032-TENANT", "envelope detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_0033(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "debug";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "debug";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0033", "redactor detector matched payload/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0033-TENANT", "redactor detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_0034(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "none";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0034", "graph detector matched quote/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0034-TENANT", "graph detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0035(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "inf";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0035", "query detector matched role/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0035-TENANT", "query detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0036(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "valid";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "stale";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0036", "telemetry detector matched cipher/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0036-TENANT", "telemetry detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_0037(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "public";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "inf";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0037", "attest detector matched ttl/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0037-TENANT", "attest detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_0038(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "closed";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "*";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0038", "package detector matched payload/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0038-TENANT", "package detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_0039(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "xor256";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "valid";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0039", "workflow detector matched quote/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0039-TENANT", "workflow detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_0040(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "requester";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "mutable";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0040", "policy detector matched role/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0040-TENANT", "policy detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_0041(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "none";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "public";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0041", "token detector matched cipher/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0041-TENANT", "token detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_0042(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "stale";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "root";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0042", "envelope detector matched ttl/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0042-TENANT", "envelope detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_0043(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "*";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "closed";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0043", "redactor detector matched payload/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0043-TENANT", "redactor detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0044(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "mutable";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "replay";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0044", "graph detector matched quote/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0044-TENANT", "graph detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0045(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "root";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "xor256";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0045", "query detector matched role/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0045-TENANT", "query detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_0046(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "replay";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "login";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0046", "telemetry detector matched cipher/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0046-TENANT", "telemetry detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_0047(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "login";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "requester";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0047", "attest detector matched ttl/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0047-TENANT", "attest detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_0048(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "debug";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "debug";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0048", "package detector matched payload/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0048-TENANT", "package detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_0049(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "none";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0049", "workflow detector matched quote/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0049-TENANT", "workflow detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_0050(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "inf";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0050", "policy detector matched role/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0050-TENANT", "policy detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_0051(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "valid";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "stale";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0051", "token detector matched cipher/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0051-TENANT", "token detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_0052(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "public";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "inf";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0052", "envelope detector matched ttl/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0052-TENANT", "envelope detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0053(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "closed";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "*";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0053", "redactor detector matched payload/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0053-TENANT", "redactor detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0054(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "xor256";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "valid";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0054", "graph detector matched quote/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0054-TENANT", "graph detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_0055(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "requester";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "mutable";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0055", "query detector matched role/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0055-TENANT", "query detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_0056(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "none";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "public";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0056", "telemetry detector matched cipher/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0056-TENANT", "telemetry detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_0057(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "stale";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "root";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0057", "attest detector matched ttl/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0057-TENANT", "attest detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_0058(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "*";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "closed";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0058", "package detector matched payload/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0058-TENANT", "package detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_0059(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "mutable";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "replay";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0059", "workflow detector matched quote/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0059-TENANT", "workflow detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_0060(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "root";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "xor256";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0060", "policy detector matched role/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0060-TENANT", "policy detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_0061(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "replay";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "login";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0061", "token detector matched cipher/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0061-TENANT", "token detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0062(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "login";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "requester";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0062", "envelope detector matched ttl/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0062-TENANT", "envelope detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0063(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "debug";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "debug";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0063", "redactor detector matched payload/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0063-TENANT", "redactor detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_0064(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "none";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0064", "graph detector matched quote/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0064-TENANT", "graph detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_0065(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "inf";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0065", "query detector matched role/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0065-TENANT", "query detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_0066(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "valid";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "stale";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0066", "telemetry detector matched cipher/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0066-TENANT", "telemetry detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_0067(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "public";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "inf";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0067", "attest detector matched ttl/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0067-TENANT", "attest detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_0068(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "closed";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "*";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0068", "package detector matched payload/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0068-TENANT", "package detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_0069(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "xor256";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "valid";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0069", "workflow detector matched quote/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0069-TENANT", "workflow detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_0070(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "requester";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "mutable";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0070", "policy detector matched role/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0070-TENANT", "policy detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0071(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "none";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "public";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0071", "token detector matched cipher/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0071-TENANT", "token detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0072(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "stale";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "root";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0072", "envelope detector matched ttl/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0072-TENANT", "envelope detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_0073(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "*";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "closed";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0073", "redactor detector matched payload/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0073-TENANT", "redactor detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_0074(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "mutable";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "replay";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0074", "graph detector matched quote/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0074-TENANT", "graph detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_0075(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "root";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "xor256";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0075", "query detector matched role/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0075-TENANT", "query detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_0076(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "replay";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "login";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0076", "telemetry detector matched cipher/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0076-TENANT", "telemetry detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_0077(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "login";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "requester";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0077", "attest detector matched ttl/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0077-TENANT", "attest detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_0078(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "debug";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "debug";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0078", "package detector matched payload/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0078-TENANT", "package detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_0079(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "none";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0079", "workflow detector matched quote/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0079-TENANT", "workflow detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0080(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "inf";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0080", "policy detector matched role/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0080-TENANT", "policy detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0081(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "valid";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "stale";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0081", "token detector matched cipher/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0081-TENANT", "token detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_0082(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "public";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "inf";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0082", "envelope detector matched ttl/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0082-TENANT", "envelope detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_0083(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "closed";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "*";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0083", "redactor detector matched payload/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0083-TENANT", "redactor detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_0084(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "xor256";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "valid";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0084", "graph detector matched quote/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0084-TENANT", "graph detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_0085(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "requester";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "mutable";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0085", "query detector matched role/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0085-TENANT", "query detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_0086(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "none";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "public";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0086", "telemetry detector matched cipher/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0086-TENANT", "telemetry detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_0087(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "stale";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "root";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0087", "attest detector matched ttl/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0087-TENANT", "attest detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_0088(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "*";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "closed";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0088", "package detector matched payload/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0088-TENANT", "package detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0089(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "mutable";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "replay";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0089", "workflow detector matched quote/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0089-TENANT", "workflow detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0090(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "root";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "xor256";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0090", "policy detector matched role/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0090-TENANT", "policy detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_0091(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "replay";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "login";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0091", "token detector matched cipher/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0091-TENANT", "token detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_0092(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "login";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "requester";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0092", "envelope detector matched ttl/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0092-TENANT", "envelope detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_0093(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "debug";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "debug";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0093", "redactor detector matched payload/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0093-TENANT", "redactor detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_0094(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "none";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0094", "graph detector matched quote/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0094-TENANT", "graph detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult run_group_00(const FieldMap& fields) {
  AnalysisResult out;
  merge(out, detector_0000(fields));
  merge(out, detector_0001(fields));
  merge(out, detector_0002(fields));
  merge(out, detector_0003(fields));
  merge(out, detector_0004(fields));
  merge(out, detector_0005(fields));
  merge(out, detector_0006(fields));
  merge(out, detector_0007(fields));
  merge(out, detector_0008(fields));
  merge(out, detector_0009(fields));
  merge(out, detector_0010(fields));
  merge(out, detector_0011(fields));
  merge(out, detector_0012(fields));
  merge(out, detector_0013(fields));
  merge(out, detector_0014(fields));
  merge(out, detector_0015(fields));
  merge(out, detector_0016(fields));
  merge(out, detector_0017(fields));
  merge(out, detector_0018(fields));
  merge(out, detector_0019(fields));
  merge(out, detector_0020(fields));
  merge(out, detector_0021(fields));
  merge(out, detector_0022(fields));
  merge(out, detector_0023(fields));
  merge(out, detector_0024(fields));
  merge(out, detector_0025(fields));
  merge(out, detector_0026(fields));
  merge(out, detector_0027(fields));
  merge(out, detector_0028(fields));
  merge(out, detector_0029(fields));
  merge(out, detector_0030(fields));
  merge(out, detector_0031(fields));
  merge(out, detector_0032(fields));
  merge(out, detector_0033(fields));
  merge(out, detector_0034(fields));
  merge(out, detector_0035(fields));
  merge(out, detector_0036(fields));
  merge(out, detector_0037(fields));
  merge(out, detector_0038(fields));
  merge(out, detector_0039(fields));
  merge(out, detector_0040(fields));
  merge(out, detector_0041(fields));
  merge(out, detector_0042(fields));
  merge(out, detector_0043(fields));
  merge(out, detector_0044(fields));
  merge(out, detector_0045(fields));
  merge(out, detector_0046(fields));
  merge(out, detector_0047(fields));
  merge(out, detector_0048(fields));
  merge(out, detector_0049(fields));
  merge(out, detector_0050(fields));
  merge(out, detector_0051(fields));
  merge(out, detector_0052(fields));
  merge(out, detector_0053(fields));
  merge(out, detector_0054(fields));
  merge(out, detector_0055(fields));
  merge(out, detector_0056(fields));
  merge(out, detector_0057(fields));
  merge(out, detector_0058(fields));
  merge(out, detector_0059(fields));
  merge(out, detector_0060(fields));
  merge(out, detector_0061(fields));
  merge(out, detector_0062(fields));
  merge(out, detector_0063(fields));
  merge(out, detector_0064(fields));
  merge(out, detector_0065(fields));
  merge(out, detector_0066(fields));
  merge(out, detector_0067(fields));
  merge(out, detector_0068(fields));
  merge(out, detector_0069(fields));
  merge(out, detector_0070(fields));
  merge(out, detector_0071(fields));
  merge(out, detector_0072(fields));
  merge(out, detector_0073(fields));
  merge(out, detector_0074(fields));
  merge(out, detector_0075(fields));
  merge(out, detector_0076(fields));
  merge(out, detector_0077(fields));
  merge(out, detector_0078(fields));
  merge(out, detector_0079(fields));
  merge(out, detector_0080(fields));
  merge(out, detector_0081(fields));
  merge(out, detector_0082(fields));
  merge(out, detector_0083(fields));
  merge(out, detector_0084(fields));
  merge(out, detector_0085(fields));
  merge(out, detector_0086(fields));
  merge(out, detector_0087(fields));
  merge(out, detector_0088(fields));
  merge(out, detector_0089(fields));
  merge(out, detector_0090(fields));
  merge(out, detector_0091(fields));
  merge(out, detector_0092(fields));
  merge(out, detector_0093(fields));
  merge(out, detector_0094(fields));
  return out;
}

}  // namespace detector_group_00
}  // namespace vaultstorm
