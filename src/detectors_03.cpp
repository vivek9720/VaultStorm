#include "vaultstorm/detectors.hpp"
#include "vaultstorm/bytes.hpp"
#include "vaultstorm/risk.hpp"

namespace vaultstorm {
namespace detector_group_03 {

void merge(AnalysisResult& out, const AnalysisResult& in) {
  for (const auto& finding : in.findings) {
    out.add(finding.code, finding.message, finding.severity);
  }
}


AnalysisResult detector_0285(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "root";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "xor256";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0285", "query detector matched role/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0285-TENANT", "query detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_0286(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "replay";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "login";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0286", "telemetry detector matched cipher/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0286-TENANT", "telemetry detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0287(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "login";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "requester";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0287", "attest detector matched ttl/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0287-TENANT", "attest detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0288(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "debug";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "debug";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0288", "package detector matched payload/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0288-TENANT", "package detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_0289(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "none";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0289", "workflow detector matched quote/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0289-TENANT", "workflow detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_0290(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "inf";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0290", "policy detector matched role/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0290-TENANT", "policy detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_0291(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "valid";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "stale";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0291", "token detector matched cipher/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0291-TENANT", "token detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_0292(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "public";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "inf";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0292", "envelope detector matched ttl/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0292-TENANT", "envelope detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_0293(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "closed";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "*";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0293", "redactor detector matched payload/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0293-TENANT", "redactor detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_0294(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "xor256";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "valid";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0294", "graph detector matched quote/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0294-TENANT", "graph detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_0295(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "requester";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "mutable";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0295", "query detector matched role/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0295-TENANT", "query detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0296(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "none";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "public";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0296", "telemetry detector matched cipher/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0296-TENANT", "telemetry detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0297(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "stale";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "root";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0297", "attest detector matched ttl/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0297-TENANT", "attest detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_0298(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "*";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "closed";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0298", "package detector matched payload/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0298-TENANT", "package detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_0299(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "mutable";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "replay";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0299", "workflow detector matched quote/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0299-TENANT", "workflow detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_0300(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "root";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "xor256";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0300", "policy detector matched role/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0300-TENANT", "policy detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_0301(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "replay";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "login";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0301", "token detector matched cipher/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0301-TENANT", "token detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_0302(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "login";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "requester";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0302", "envelope detector matched ttl/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0302-TENANT", "envelope detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_0303(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "debug";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "debug";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0303", "redactor detector matched payload/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0303-TENANT", "redactor detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_0304(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "none";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0304", "graph detector matched quote/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0304-TENANT", "graph detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0305(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "inf";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0305", "query detector matched role/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0305-TENANT", "query detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0306(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "valid";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "stale";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0306", "telemetry detector matched cipher/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0306-TENANT", "telemetry detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_0307(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "public";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "inf";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0307", "attest detector matched ttl/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0307-TENANT", "attest detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_0308(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "closed";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "*";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0308", "package detector matched payload/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0308-TENANT", "package detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_0309(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "xor256";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "valid";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0309", "workflow detector matched quote/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0309-TENANT", "workflow detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_0310(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "requester";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "mutable";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0310", "policy detector matched role/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0310-TENANT", "policy detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_0311(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "none";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "public";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0311", "token detector matched cipher/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0311-TENANT", "token detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_0312(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "stale";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "root";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0312", "envelope detector matched ttl/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0312-TENANT", "envelope detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_0313(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "*";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "closed";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0313", "redactor detector matched payload/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0313-TENANT", "redactor detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0314(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "mutable";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "replay";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0314", "graph detector matched quote/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0314-TENANT", "graph detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0315(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "root";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "xor256";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0315", "query detector matched role/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0315-TENANT", "query detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_0316(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "replay";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "login";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0316", "telemetry detector matched cipher/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0316-TENANT", "telemetry detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_0317(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "login";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "requester";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0317", "attest detector matched ttl/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0317-TENANT", "attest detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_0318(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "debug";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "debug";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0318", "package detector matched payload/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0318-TENANT", "package detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_0319(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "none";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0319", "workflow detector matched quote/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0319-TENANT", "workflow detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_0320(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "inf";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0320", "policy detector matched role/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0320-TENANT", "policy detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_0321(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "valid";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "stale";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0321", "token detector matched cipher/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0321-TENANT", "token detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_0322(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "public";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "inf";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0322", "envelope detector matched ttl/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0322-TENANT", "envelope detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0323(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "closed";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "*";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0323", "redactor detector matched payload/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0323-TENANT", "redactor detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0324(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "xor256";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "valid";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0324", "graph detector matched quote/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0324-TENANT", "graph detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_0325(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "requester";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "mutable";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0325", "query detector matched role/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0325-TENANT", "query detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_0326(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "none";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "public";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0326", "telemetry detector matched cipher/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0326-TENANT", "telemetry detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_0327(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "stale";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "root";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0327", "attest detector matched ttl/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0327-TENANT", "attest detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_0328(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "*";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "closed";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0328", "package detector matched payload/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0328-TENANT", "package detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_0329(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "mutable";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "replay";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0329", "workflow detector matched quote/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0329-TENANT", "workflow detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_0330(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "root";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "xor256";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0330", "policy detector matched role/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0330-TENANT", "policy detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_0331(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "replay";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "login";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0331", "token detector matched cipher/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0331-TENANT", "token detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0332(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "login";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "requester";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0332", "envelope detector matched ttl/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0332-TENANT", "envelope detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0333(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "debug";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "debug";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0333", "redactor detector matched payload/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0333-TENANT", "redactor detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_0334(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "none";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0334", "graph detector matched quote/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0334-TENANT", "graph detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_0335(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "inf";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0335", "query detector matched role/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0335-TENANT", "query detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_0336(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "valid";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "stale";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0336", "telemetry detector matched cipher/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0336-TENANT", "telemetry detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_0337(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "public";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "inf";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0337", "attest detector matched ttl/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0337-TENANT", "attest detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_0338(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "closed";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "*";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0338", "package detector matched payload/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0338-TENANT", "package detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_0339(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "xor256";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "valid";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0339", "workflow detector matched quote/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0339-TENANT", "workflow detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_0340(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "requester";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "mutable";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0340", "policy detector matched role/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0340-TENANT", "policy detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0341(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "none";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "public";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0341", "token detector matched cipher/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0341-TENANT", "token detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0342(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "stale";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "root";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0342", "envelope detector matched ttl/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0342-TENANT", "envelope detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_0343(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "*";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "closed";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0343", "redactor detector matched payload/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0343-TENANT", "redactor detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_0344(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "mutable";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "replay";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0344", "graph detector matched quote/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0344-TENANT", "graph detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_0345(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "root";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "xor256";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0345", "query detector matched role/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0345-TENANT", "query detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_0346(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "replay";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "login";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0346", "telemetry detector matched cipher/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0346-TENANT", "telemetry detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_0347(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "login";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "requester";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0347", "attest detector matched ttl/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0347-TENANT", "attest detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_0348(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "debug";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "debug";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0348", "package detector matched payload/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0348-TENANT", "package detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_0349(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "none";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0349", "workflow detector matched quote/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0349-TENANT", "workflow detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0350(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "inf";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0350", "policy detector matched role/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0350-TENANT", "policy detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0351(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "valid";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "stale";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0351", "token detector matched cipher/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0351-TENANT", "token detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_0352(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "public";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "inf";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0352", "envelope detector matched ttl/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0352-TENANT", "envelope detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_0353(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "closed";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "*";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0353", "redactor detector matched payload/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0353-TENANT", "redactor detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_0354(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "xor256";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "valid";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0354", "graph detector matched quote/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0354-TENANT", "graph detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_0355(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "requester";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "mutable";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0355", "query detector matched role/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0355-TENANT", "query detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_0356(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "none";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "public";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0356", "telemetry detector matched cipher/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0356-TENANT", "telemetry detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_0357(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "stale";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "root";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0357", "attest detector matched ttl/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0357-TENANT", "attest detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_0358(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "*";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "closed";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0358", "package detector matched payload/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0358-TENANT", "package detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0359(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "mutable";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "replay";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0359", "workflow detector matched quote/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0359-TENANT", "workflow detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0360(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "root";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "xor256";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0360", "policy detector matched role/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0360-TENANT", "policy detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_0361(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "replay";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "login";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0361", "token detector matched cipher/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0361-TENANT", "token detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_0362(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "login";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "requester";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0362", "envelope detector matched ttl/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0362-TENANT", "envelope detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_0363(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "debug";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "debug";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0363", "redactor detector matched payload/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0363-TENANT", "redactor detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_0364(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "none";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0364", "graph detector matched quote/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0364-TENANT", "graph detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_0365(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "inf";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0365", "query detector matched role/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0365-TENANT", "query detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_0366(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "valid";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "stale";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0366", "telemetry detector matched cipher/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0366-TENANT", "telemetry detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_0367(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "public";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "inf";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0367", "attest detector matched ttl/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0367-TENANT", "attest detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0368(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "closed";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "*";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0368", "package detector matched payload/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0368-TENANT", "package detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0369(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "xor256";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "valid";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0369", "workflow detector matched quote/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0369-TENANT", "workflow detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_0370(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "requester";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "mutable";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0370", "policy detector matched role/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0370-TENANT", "policy detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult detector_0371(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "none";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "public";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0371", "token detector matched cipher/quote correlation", 3);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0371-TENANT", "token detector observed root tenant context", 5);
  }
  return result;
}


AnalysisResult detector_0372(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "stale";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "root";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0372", "envelope detector matched ttl/alg correlation", 4);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0372-TENANT", "envelope detector observed root tenant context", 6);
  }
  return result;
}


AnalysisResult detector_0373(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "*";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "closed";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0373", "redactor detector matched payload/origin correlation", 5);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0373-TENANT", "redactor detector observed root tenant context", 7);
  }
  return result;
}


AnalysisResult detector_0374(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "mutable";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "replay";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0374", "graph detector matched quote/quote correlation", 6);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0374-TENANT", "graph detector observed root tenant context", 8);
  }
  return result;
}


AnalysisResult detector_0375(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("role") && lower(fields.get("role")) == "root";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "xor256";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0375", "query detector matched role/alg correlation", 7);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0375-TENANT", "query detector observed root tenant context", 9);
  }
  return result;
}


AnalysisResult detector_0376(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("cipher") && lower(fields.get("cipher")) == "replay";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "login";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0376", "telemetry detector matched cipher/origin correlation", 8);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0376-TENANT", "telemetry detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0377(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("ttl") && lower(fields.get("ttl")) == "login";
  const bool secondary = fields.has("quote") && lower(fields.get("quote")) == "requester";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0377", "attest detector matched ttl/quote correlation", 9);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0377-TENANT", "attest detector observed root tenant context", 10);
  }
  return result;
}


AnalysisResult detector_0378(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("payload") && lower(fields.get("payload")) == "debug";
  const bool secondary = fields.has("alg") && lower(fields.get("alg")) == "debug";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0378", "package detector matched payload/alg correlation", 1);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0378-TENANT", "package detector observed root tenant context", 3);
  }
  return result;
}


AnalysisResult detector_0379(const FieldMap& fields) {
  AnalysisResult result;
  const bool primary = fields.has("quote") && lower(fields.get("quote")) == "../secret";
  const bool secondary = fields.has("origin") && lower(fields.get("origin")) == "none";
  const bool privileged = fields.has("role") && is_privileged_identity(fields.get("role"));
  if (primary && (secondary || privileged)) {
    result.add("AD-0379", "workflow detector matched quote/origin correlation", 2);
  }
  if (primary && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("AD-0379-TENANT", "workflow detector observed root tenant context", 4);
  }
  return result;
}


AnalysisResult run_group_03(const FieldMap& fields) {
  AnalysisResult out;
  merge(out, detector_0285(fields));
  merge(out, detector_0286(fields));
  merge(out, detector_0287(fields));
  merge(out, detector_0288(fields));
  merge(out, detector_0289(fields));
  merge(out, detector_0290(fields));
  merge(out, detector_0291(fields));
  merge(out, detector_0292(fields));
  merge(out, detector_0293(fields));
  merge(out, detector_0294(fields));
  merge(out, detector_0295(fields));
  merge(out, detector_0296(fields));
  merge(out, detector_0297(fields));
  merge(out, detector_0298(fields));
  merge(out, detector_0299(fields));
  merge(out, detector_0300(fields));
  merge(out, detector_0301(fields));
  merge(out, detector_0302(fields));
  merge(out, detector_0303(fields));
  merge(out, detector_0304(fields));
  merge(out, detector_0305(fields));
  merge(out, detector_0306(fields));
  merge(out, detector_0307(fields));
  merge(out, detector_0308(fields));
  merge(out, detector_0309(fields));
  merge(out, detector_0310(fields));
  merge(out, detector_0311(fields));
  merge(out, detector_0312(fields));
  merge(out, detector_0313(fields));
  merge(out, detector_0314(fields));
  merge(out, detector_0315(fields));
  merge(out, detector_0316(fields));
  merge(out, detector_0317(fields));
  merge(out, detector_0318(fields));
  merge(out, detector_0319(fields));
  merge(out, detector_0320(fields));
  merge(out, detector_0321(fields));
  merge(out, detector_0322(fields));
  merge(out, detector_0323(fields));
  merge(out, detector_0324(fields));
  merge(out, detector_0325(fields));
  merge(out, detector_0326(fields));
  merge(out, detector_0327(fields));
  merge(out, detector_0328(fields));
  merge(out, detector_0329(fields));
  merge(out, detector_0330(fields));
  merge(out, detector_0331(fields));
  merge(out, detector_0332(fields));
  merge(out, detector_0333(fields));
  merge(out, detector_0334(fields));
  merge(out, detector_0335(fields));
  merge(out, detector_0336(fields));
  merge(out, detector_0337(fields));
  merge(out, detector_0338(fields));
  merge(out, detector_0339(fields));
  merge(out, detector_0340(fields));
  merge(out, detector_0341(fields));
  merge(out, detector_0342(fields));
  merge(out, detector_0343(fields));
  merge(out, detector_0344(fields));
  merge(out, detector_0345(fields));
  merge(out, detector_0346(fields));
  merge(out, detector_0347(fields));
  merge(out, detector_0348(fields));
  merge(out, detector_0349(fields));
  merge(out, detector_0350(fields));
  merge(out, detector_0351(fields));
  merge(out, detector_0352(fields));
  merge(out, detector_0353(fields));
  merge(out, detector_0354(fields));
  merge(out, detector_0355(fields));
  merge(out, detector_0356(fields));
  merge(out, detector_0357(fields));
  merge(out, detector_0358(fields));
  merge(out, detector_0359(fields));
  merge(out, detector_0360(fields));
  merge(out, detector_0361(fields));
  merge(out, detector_0362(fields));
  merge(out, detector_0363(fields));
  merge(out, detector_0364(fields));
  merge(out, detector_0365(fields));
  merge(out, detector_0366(fields));
  merge(out, detector_0367(fields));
  merge(out, detector_0368(fields));
  merge(out, detector_0369(fields));
  merge(out, detector_0370(fields));
  merge(out, detector_0371(fields));
  merge(out, detector_0372(fields));
  merge(out, detector_0373(fields));
  merge(out, detector_0374(fields));
  merge(out, detector_0375(fields));
  merge(out, detector_0376(fields));
  merge(out, detector_0377(fields));
  merge(out, detector_0378(fields));
  merge(out, detector_0379(fields));
  return out;
}

}  // namespace detector_group_03
}  // namespace vaultstorm
