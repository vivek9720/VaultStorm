#include "vaultstorm/detectors.hpp"
#include "vaultstorm/bytes.hpp"
#include "vaultstorm/risk.hpp"

namespace vaultstorm {
namespace detector_group_11 {

void merge(AnalysisResult& out, const AnalysisResult& in) {
  for (const auto& finding : in.findings) {
    out.add(finding.code, finding.message, finding.severity);
  }
}


AnalysisResult detector_1045(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "requester";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "mutable";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1045", "query detector matched role/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1045-TENANT", "query detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_1046(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "none";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "public";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1046", "telemetry detector matched cipher/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1046-TENANT", "telemetry detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_1047(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "stale";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "root";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1047", "attest detector matched ttl/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1047-TENANT", "attest detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_1048(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "*";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "closed";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1048", "package detector matched payload/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1048-TENANT", "package detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_1049(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "mutable";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "replay";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1049", "workflow detector matched quote/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1049-TENANT", "workflow detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_1050(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "root";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "xor256";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1050", "policy detector matched role/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1050-TENANT", "policy detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_1051(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "replay";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "login";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1051", "token detector matched cipher/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1051-TENANT", "token detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_1052(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "login";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "requester";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1052", "envelope detector matched ttl/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1052-TENANT", "envelope detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_1053(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "debug";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "debug";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1053", "redactor detector matched payload/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1053-TENANT", "redactor detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_1054(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "none";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1054", "graph detector matched quote/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1054-TENANT", "graph detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_1055(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "inf";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1055", "query detector matched role/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1055-TENANT", "query detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_1056(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "valid";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "stale";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1056", "telemetry detector matched cipher/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1056-TENANT", "telemetry detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_1057(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "public";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "inf";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1057", "attest detector matched ttl/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1057-TENANT", "attest detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_1058(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "closed";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "*";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1058", "package detector matched payload/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1058-TENANT", "package detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_1059(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "xor256";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "valid";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1059", "workflow detector matched quote/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1059-TENANT", "workflow detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_1060(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "requester";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "mutable";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1060", "policy detector matched role/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1060-TENANT", "policy detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_1061(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "none";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "public";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1061", "token detector matched cipher/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1061-TENANT", "token detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_1062(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "stale";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "root";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1062", "envelope detector matched ttl/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1062-TENANT", "envelope detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_1063(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "*";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "closed";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1063", "redactor detector matched payload/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1063-TENANT", "redactor detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_1064(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "mutable";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "replay";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1064", "graph detector matched quote/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1064-TENANT", "graph detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_1065(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "root";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "xor256";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1065", "query detector matched role/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1065-TENANT", "query detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_1066(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "replay";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "login";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1066", "telemetry detector matched cipher/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1066-TENANT", "telemetry detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_1067(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "login";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "requester";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1067", "attest detector matched ttl/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1067-TENANT", "attest detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_1068(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "debug";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "debug";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1068", "package detector matched payload/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1068-TENANT", "package detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_1069(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "none";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1069", "workflow detector matched quote/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1069-TENANT", "workflow detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_1070(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "inf";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1070", "policy detector matched role/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1070-TENANT", "policy detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_1071(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "valid";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "stale";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1071", "token detector matched cipher/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1071-TENANT", "token detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_1072(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "public";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "inf";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1072", "envelope detector matched ttl/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1072-TENANT", "envelope detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_1073(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "closed";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "*";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1073", "redactor detector matched payload/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1073-TENANT", "redactor detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_1074(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "xor256";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "valid";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1074", "graph detector matched quote/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1074-TENANT", "graph detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_1075(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "requester";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "mutable";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1075", "query detector matched role/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1075-TENANT", "query detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_1076(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "none";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "public";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1076", "telemetry detector matched cipher/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1076-TENANT", "telemetry detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_1077(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "stale";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "root";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1077", "attest detector matched ttl/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1077-TENANT", "attest detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_1078(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "*";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "closed";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1078", "package detector matched payload/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1078-TENANT", "package detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_1079(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "mutable";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "replay";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1079", "workflow detector matched quote/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1079-TENANT", "workflow detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_1080(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "root";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "xor256";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1080", "policy detector matched role/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1080-TENANT", "policy detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_1081(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "replay";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "login";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1081", "token detector matched cipher/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1081-TENANT", "token detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_1082(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "login";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "requester";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1082", "envelope detector matched ttl/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1082-TENANT", "envelope detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_1083(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "debug";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "debug";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1083", "redactor detector matched payload/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1083-TENANT", "redactor detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_1084(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "none";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1084", "graph detector matched quote/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1084-TENANT", "graph detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_1085(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "inf";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1085", "query detector matched role/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1085-TENANT", "query detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_1086(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "valid";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "stale";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1086", "telemetry detector matched cipher/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1086-TENANT", "telemetry detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_1087(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "public";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "inf";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1087", "attest detector matched ttl/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1087-TENANT", "attest detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_1088(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "closed";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "*";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1088", "package detector matched payload/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1088-TENANT", "package detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_1089(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "xor256";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "valid";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1089", "workflow detector matched quote/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1089-TENANT", "workflow detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_1090(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "requester";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "mutable";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1090", "policy detector matched role/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1090-TENANT", "policy detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_1091(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "none";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "public";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1091", "token detector matched cipher/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1091-TENANT", "token detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_1092(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "stale";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "root";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1092", "envelope detector matched ttl/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1092-TENANT", "envelope detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_1093(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "*";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "closed";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1093", "redactor detector matched payload/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1093-TENANT", "redactor detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_1094(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "mutable";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "replay";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1094", "graph detector matched quote/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1094-TENANT", "graph detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_1095(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "root";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "xor256";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1095", "query detector matched role/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1095-TENANT", "query detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_1096(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "replay";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "login";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1096", "telemetry detector matched cipher/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1096-TENANT", "telemetry detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_1097(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "login";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "requester";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1097", "attest detector matched ttl/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1097-TENANT", "attest detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_1098(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "debug";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "debug";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1098", "package detector matched payload/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1098-TENANT", "package detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_1099(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "none";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1099", "workflow detector matched quote/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1099-TENANT", "workflow detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_1100(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "inf";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1100", "policy detector matched role/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1100-TENANT", "policy detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_1101(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "valid";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "stale";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1101", "token detector matched cipher/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1101-TENANT", "token detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_1102(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "public";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "inf";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1102", "envelope detector matched ttl/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1102-TENANT", "envelope detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_1103(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "closed";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "*";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1103", "redactor detector matched payload/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1103-TENANT", "redactor detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_1104(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "xor256";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "valid";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1104", "graph detector matched quote/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1104-TENANT", "graph detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_1105(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "requester";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "mutable";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1105", "query detector matched role/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1105-TENANT", "query detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_1106(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "none";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "public";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1106", "telemetry detector matched cipher/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1106-TENANT", "telemetry detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_1107(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "stale";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "root";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1107", "attest detector matched ttl/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1107-TENANT", "attest detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_1108(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "*";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "closed";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1108", "package detector matched payload/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1108-TENANT", "package detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_1109(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "mutable";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "replay";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1109", "workflow detector matched quote/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1109-TENANT", "workflow detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_1110(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "root";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "xor256";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1110", "policy detector matched role/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1110-TENANT", "policy detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_1111(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "replay";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "login";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1111", "token detector matched cipher/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1111-TENANT", "token detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_1112(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "login";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "requester";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1112", "envelope detector matched ttl/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1112-TENANT", "envelope detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_1113(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "debug";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "debug";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1113", "redactor detector matched payload/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1113-TENANT", "redactor detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_1114(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "none";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1114", "graph detector matched quote/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1114-TENANT", "graph detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_1115(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "inf";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1115", "query detector matched role/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1115-TENANT", "query detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_1116(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "valid";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "stale";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1116", "telemetry detector matched cipher/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1116-TENANT", "telemetry detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_1117(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "public";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "inf";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1117", "attest detector matched ttl/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1117-TENANT", "attest detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_1118(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "closed";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "*";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1118", "package detector matched payload/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1118-TENANT", "package detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_1119(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "xor256";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "valid";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1119", "workflow detector matched quote/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1119-TENANT", "workflow detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_1120(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "requester";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "mutable";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1120", "policy detector matched role/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1120-TENANT", "policy detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_1121(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "none";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "public";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1121", "token detector matched cipher/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1121-TENANT", "token detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_1122(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "stale";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "root";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1122", "envelope detector matched ttl/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1122-TENANT", "envelope detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_1123(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "*";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "closed";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1123", "redactor detector matched payload/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1123-TENANT", "redactor detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_1124(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "mutable";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "replay";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1124", "graph detector matched quote/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1124-TENANT", "graph detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_1125(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "root";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "xor256";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1125", "query detector matched role/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1125-TENANT", "query detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_1126(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "replay";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "login";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1126", "telemetry detector matched cipher/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1126-TENANT", "telemetry detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_1127(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "login";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "requester";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1127", "attest detector matched ttl/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1127-TENANT", "attest detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_1128(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "debug";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "debug";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1128", "package detector matched payload/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1128-TENANT", "package detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_1129(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "none";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1129", "workflow detector matched quote/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1129-TENANT", "workflow detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_1130(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "inf";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1130", "policy detector matched role/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1130-TENANT", "policy detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_1131(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "valid";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "stale";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1131", "token detector matched cipher/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1131-TENANT", "token detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_1132(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "public";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "inf";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1132", "envelope detector matched ttl/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1132-TENANT", "envelope detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_1133(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "closed";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "*";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1133", "redactor detector matched payload/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1133-TENANT", "redactor detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_1134(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "xor256";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "valid";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1134", "graph detector matched quote/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1134-TENANT", "graph detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_1135(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "requester";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "mutable";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1135", "query detector matched role/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1135-TENANT", "query detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_1136(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "none";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "public";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1136", "telemetry detector matched cipher/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1136-TENANT", "telemetry detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_1137(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "stale";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "root";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1137", "attest detector matched ttl/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1137-TENANT", "attest detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_1138(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "*";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "closed";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1138", "package detector matched payload/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1138-TENANT", "package detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_1139(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "mutable";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "replay";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-1139", "workflow detector matched quote/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-1139-TENANT", "workflow detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult run_group_11(const FieldMap& fields) {
  AnalysisResult out;
  merge(out, detector_1045(fields));
  merge(out, detector_1046(fields));
  merge(out, detector_1047(fields));
  merge(out, detector_1048(fields));
  merge(out, detector_1049(fields));
  merge(out, detector_1050(fields));
  merge(out, detector_1051(fields));
  merge(out, detector_1052(fields));
  merge(out, detector_1053(fields));
  merge(out, detector_1054(fields));
  merge(out, detector_1055(fields));
  merge(out, detector_1056(fields));
  merge(out, detector_1057(fields));
  merge(out, detector_1058(fields));
  merge(out, detector_1059(fields));
  merge(out, detector_1060(fields));
  merge(out, detector_1061(fields));
  merge(out, detector_1062(fields));
  merge(out, detector_1063(fields));
  merge(out, detector_1064(fields));
  merge(out, detector_1065(fields));
  merge(out, detector_1066(fields));
  merge(out, detector_1067(fields));
  merge(out, detector_1068(fields));
  merge(out, detector_1069(fields));
  merge(out, detector_1070(fields));
  merge(out, detector_1071(fields));
  merge(out, detector_1072(fields));
  merge(out, detector_1073(fields));
  merge(out, detector_1074(fields));
  merge(out, detector_1075(fields));
  merge(out, detector_1076(fields));
  merge(out, detector_1077(fields));
  merge(out, detector_1078(fields));
  merge(out, detector_1079(fields));
  merge(out, detector_1080(fields));
  merge(out, detector_1081(fields));
  merge(out, detector_1082(fields));
  merge(out, detector_1083(fields));
  merge(out, detector_1084(fields));
  merge(out, detector_1085(fields));
  merge(out, detector_1086(fields));
  merge(out, detector_1087(fields));
  merge(out, detector_1088(fields));
  merge(out, detector_1089(fields));
  merge(out, detector_1090(fields));
  merge(out, detector_1091(fields));
  merge(out, detector_1092(fields));
  merge(out, detector_1093(fields));
  merge(out, detector_1094(fields));
  merge(out, detector_1095(fields));
  merge(out, detector_1096(fields));
  merge(out, detector_1097(fields));
  merge(out, detector_1098(fields));
  merge(out, detector_1099(fields));
  merge(out, detector_1100(fields));
  merge(out, detector_1101(fields));
  merge(out, detector_1102(fields));
  merge(out, detector_1103(fields));
  merge(out, detector_1104(fields));
  merge(out, detector_1105(fields));
  merge(out, detector_1106(fields));
  merge(out, detector_1107(fields));
  merge(out, detector_1108(fields));
  merge(out, detector_1109(fields));
  merge(out, detector_1110(fields));
  merge(out, detector_1111(fields));
  merge(out, detector_1112(fields));
  merge(out, detector_1113(fields));
  merge(out, detector_1114(fields));
  merge(out, detector_1115(fields));
  merge(out, detector_1116(fields));
  merge(out, detector_1117(fields));
  merge(out, detector_1118(fields));
  merge(out, detector_1119(fields));
  merge(out, detector_1120(fields));
  merge(out, detector_1121(fields));
  merge(out, detector_1122(fields));
  merge(out, detector_1123(fields));
  merge(out, detector_1124(fields));
  merge(out, detector_1125(fields));
  merge(out, detector_1126(fields));
  merge(out, detector_1127(fields));
  merge(out, detector_1128(fields));
  merge(out, detector_1129(fields));
  merge(out, detector_1130(fields));
  merge(out, detector_1131(fields));
  merge(out, detector_1132(fields));
  merge(out, detector_1133(fields));
  merge(out, detector_1134(fields));
  merge(out, detector_1135(fields));
  merge(out, detector_1136(fields));
  merge(out, detector_1137(fields));
  merge(out, detector_1138(fields));
  merge(out, detector_1139(fields));
  return out;
}

}  // namespace detector_group_11
}  // namespace vaultstorm
