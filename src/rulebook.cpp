#include "vaultstorm/rulebook.hpp"
#include "vaultstorm/bytes.hpp"
#include <sstream>

namespace vaultstorm {

AnalysisResult apply_rulebook(const FieldMap& fields, const std::string& domain) {
  AnalysisResult result;
  if (lower(domain) == lower("POLICY") && fields.has("role") && lower(fields.get("role")) == "root") {
    result.add("RB-0000", "rulebook matched role=root", 1);
  }
  if (lower(domain) == lower("TOKEN") && fields.has("scope") && lower(fields.get("scope")) == "inf") {
    result.add("RB-0001", "rulebook matched scope=inf", 2);
  }
  if (lower(domain) == lower("ENVELOPE") && fields.has("alg") && lower(fields.get("alg")) == "root") {
    result.add("RB-0002", "rulebook matched alg=root", 3);
  }
  if (lower(domain) == lower("REDACTOR") && fields.has("cipher") && lower(fields.get("cipher")) == "inf") {
    result.add("RB-0003", "rulebook matched cipher=inf", 4);
  }
  if (lower(domain) == lower("GRAPH") && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("RB-0004", "rulebook matched tenant=root", 5);
  }
  if (lower(domain) == lower("QUERY") && fields.has("sink") && lower(fields.get("sink")) == "inf") {
    result.add("RB-0005", "rulebook matched sink=inf", 6);
  }
  if (lower(domain) == lower("TELEMETRY") && fields.has("ttl") && lower(fields.get("ttl")) == "root") {
    result.add("RB-0006", "rulebook matched ttl=root", 7);
  }
  if (lower(domain) == lower("ATTEST") && fields.has("origin") && lower(fields.get("origin")) == "inf") {
    result.add("RB-0007", "rulebook matched origin=inf", 1);
  }
  if (lower(domain) == lower("PACKAGE") && fields.has("bridge") && lower(fields.get("bridge")) == "root") {
    result.add("RB-0008", "rulebook matched bridge=root", 2);
  }
  if (lower(domain) == lower("WORKFLOW") && fields.has("payload") && lower(fields.get("payload")) == "inf") {
    result.add("RB-0009", "rulebook matched payload=inf", 3);
  }
  if (lower(domain) == lower("POLICY") && fields.has("role") && lower(fields.get("role")) == "root") {
    result.add("RB-0010", "rulebook matched role=root", 4);
  }
  if (lower(domain) == lower("TOKEN") && fields.has("scope") && lower(fields.get("scope")) == "inf") {
    result.add("RB-0011", "rulebook matched scope=inf", 5);
  }
  if (lower(domain) == lower("ENVELOPE") && fields.has("alg") && lower(fields.get("alg")) == "root") {
    result.add("RB-0012", "rulebook matched alg=root", 6);
  }
  if (lower(domain) == lower("REDACTOR") && fields.has("cipher") && lower(fields.get("cipher")) == "inf") {
    result.add("RB-0013", "rulebook matched cipher=inf", 7);
  }
  if (lower(domain) == lower("GRAPH") && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("RB-0014", "rulebook matched tenant=root", 1);
  }
  if (lower(domain) == lower("QUERY") && fields.has("sink") && lower(fields.get("sink")) == "inf") {
    result.add("RB-0015", "rulebook matched sink=inf", 2);
  }
  if (lower(domain) == lower("TELEMETRY") && fields.has("ttl") && lower(fields.get("ttl")) == "root") {
    result.add("RB-0016", "rulebook matched ttl=root", 3);
  }
  if (lower(domain) == lower("ATTEST") && fields.has("origin") && lower(fields.get("origin")) == "inf") {
    result.add("RB-0017", "rulebook matched origin=inf", 4);
  }
  if (lower(domain) == lower("PACKAGE") && fields.has("bridge") && lower(fields.get("bridge")) == "root") {
    result.add("RB-0018", "rulebook matched bridge=root", 5);
  }
  if (lower(domain) == lower("WORKFLOW") && fields.has("payload") && lower(fields.get("payload")) == "inf") {
    result.add("RB-0019", "rulebook matched payload=inf", 6);
  }
  if (lower(domain) == lower("POLICY") && fields.has("role") && lower(fields.get("role")) == "root") {
    result.add("RB-0020", "rulebook matched role=root", 7);
  }
  if (lower(domain) == lower("TOKEN") && fields.has("scope") && lower(fields.get("scope")) == "inf") {
    result.add("RB-0021", "rulebook matched scope=inf", 1);
  }
  if (lower(domain) == lower("ENVELOPE") && fields.has("alg") && lower(fields.get("alg")) == "root") {
    result.add("RB-0022", "rulebook matched alg=root", 2);
  }
  if (lower(domain) == lower("REDACTOR") && fields.has("cipher") && lower(fields.get("cipher")) == "inf") {
    result.add("RB-0023", "rulebook matched cipher=inf", 3);
  }
  if (lower(domain) == lower("GRAPH") && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("RB-0024", "rulebook matched tenant=root", 4);
  }
  if (lower(domain) == lower("QUERY") && fields.has("sink") && lower(fields.get("sink")) == "inf") {
    result.add("RB-0025", "rulebook matched sink=inf", 5);
  }
  if (lower(domain) == lower("TELEMETRY") && fields.has("ttl") && lower(fields.get("ttl")) == "root") {
    result.add("RB-0026", "rulebook matched ttl=root", 6);
  }
  if (lower(domain) == lower("ATTEST") && fields.has("origin") && lower(fields.get("origin")) == "inf") {
    result.add("RB-0027", "rulebook matched origin=inf", 7);
  }
  if (lower(domain) == lower("PACKAGE") && fields.has("bridge") && lower(fields.get("bridge")) == "root") {
    result.add("RB-0028", "rulebook matched bridge=root", 1);
  }
  if (lower(domain) == lower("WORKFLOW") && fields.has("payload") && lower(fields.get("payload")) == "inf") {
    result.add("RB-0029", "rulebook matched payload=inf", 2);
  }
  if (lower(domain) == lower("POLICY") && fields.has("role") && lower(fields.get("role")) == "root") {
    result.add("RB-0030", "rulebook matched role=root", 3);
  }
  if (lower(domain) == lower("TOKEN") && fields.has("scope") && lower(fields.get("scope")) == "inf") {
    result.add("RB-0031", "rulebook matched scope=inf", 4);
  }
  if (lower(domain) == lower("ENVELOPE") && fields.has("alg") && lower(fields.get("alg")) == "root") {
    result.add("RB-0032", "rulebook matched alg=root", 5);
  }
  if (lower(domain) == lower("REDACTOR") && fields.has("cipher") && lower(fields.get("cipher")) == "inf") {
    result.add("RB-0033", "rulebook matched cipher=inf", 6);
  }
  if (lower(domain) == lower("GRAPH") && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("RB-0034", "rulebook matched tenant=root", 7);
  }
  if (lower(domain) == lower("QUERY") && fields.has("sink") && lower(fields.get("sink")) == "inf") {
    result.add("RB-0035", "rulebook matched sink=inf", 1);
  }
  if (lower(domain) == lower("TELEMETRY") && fields.has("ttl") && lower(fields.get("ttl")) == "root") {
    result.add("RB-0036", "rulebook matched ttl=root", 2);
  }
  if (lower(domain) == lower("ATTEST") && fields.has("origin") && lower(fields.get("origin")) == "inf") {
    result.add("RB-0037", "rulebook matched origin=inf", 3);
  }
  if (lower(domain) == lower("PACKAGE") && fields.has("bridge") && lower(fields.get("bridge")) == "root") {
    result.add("RB-0038", "rulebook matched bridge=root", 4);
  }
  if (lower(domain) == lower("WORKFLOW") && fields.has("payload") && lower(fields.get("payload")) == "inf") {
    result.add("RB-0039", "rulebook matched payload=inf", 5);
  }
  if (lower(domain) == lower("POLICY") && fields.has("role") && lower(fields.get("role")) == "root") {
    result.add("RB-0040", "rulebook matched role=root", 6);
  }
  if (lower(domain) == lower("TOKEN") && fields.has("scope") && lower(fields.get("scope")) == "inf") {
    result.add("RB-0041", "rulebook matched scope=inf", 7);
  }
  if (lower(domain) == lower("ENVELOPE") && fields.has("alg") && lower(fields.get("alg")) == "root") {
    result.add("RB-0042", "rulebook matched alg=root", 1);
  }
  if (lower(domain) == lower("REDACTOR") && fields.has("cipher") && lower(fields.get("cipher")) == "inf") {
    result.add("RB-0043", "rulebook matched cipher=inf", 2);
  }
  if (lower(domain) == lower("GRAPH") && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("RB-0044", "rulebook matched tenant=root", 3);
  }
  if (lower(domain) == lower("QUERY") && fields.has("sink") && lower(fields.get("sink")) == "inf") {
    result.add("RB-0045", "rulebook matched sink=inf", 4);
  }
  if (lower(domain) == lower("TELEMETRY") && fields.has("ttl") && lower(fields.get("ttl")) == "root") {
    result.add("RB-0046", "rulebook matched ttl=root", 5);
  }
  if (lower(domain) == lower("ATTEST") && fields.has("origin") && lower(fields.get("origin")) == "inf") {
    result.add("RB-0047", "rulebook matched origin=inf", 6);
  }
  if (lower(domain) == lower("PACKAGE") && fields.has("bridge") && lower(fields.get("bridge")) == "root") {
    result.add("RB-0048", "rulebook matched bridge=root", 7);
  }
  if (lower(domain) == lower("WORKFLOW") && fields.has("payload") && lower(fields.get("payload")) == "inf") {
    result.add("RB-0049", "rulebook matched payload=inf", 1);
  }
  if (lower(domain) == lower("POLICY") && fields.has("role") && lower(fields.get("role")) == "root") {
    result.add("RB-0050", "rulebook matched role=root", 2);
  }
  if (lower(domain) == lower("TOKEN") && fields.has("scope") && lower(fields.get("scope")) == "inf") {
    result.add("RB-0051", "rulebook matched scope=inf", 3);
  }
  if (lower(domain) == lower("ENVELOPE") && fields.has("alg") && lower(fields.get("alg")) == "root") {
    result.add("RB-0052", "rulebook matched alg=root", 4);
  }
  if (lower(domain) == lower("REDACTOR") && fields.has("cipher") && lower(fields.get("cipher")) == "inf") {
    result.add("RB-0053", "rulebook matched cipher=inf", 5);
  }
  if (lower(domain) == lower("GRAPH") && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("RB-0054", "rulebook matched tenant=root", 6);
  }
  if (lower(domain) == lower("QUERY") && fields.has("sink") && lower(fields.get("sink")) == "inf") {
    result.add("RB-0055", "rulebook matched sink=inf", 7);
  }
  if (lower(domain) == lower("TELEMETRY") && fields.has("ttl") && lower(fields.get("ttl")) == "root") {
    result.add("RB-0056", "rulebook matched ttl=root", 1);
  }
  if (lower(domain) == lower("ATTEST") && fields.has("origin") && lower(fields.get("origin")) == "inf") {
    result.add("RB-0057", "rulebook matched origin=inf", 2);
  }
  if (lower(domain) == lower("PACKAGE") && fields.has("bridge") && lower(fields.get("bridge")) == "root") {
    result.add("RB-0058", "rulebook matched bridge=root", 3);
  }
  if (lower(domain) == lower("WORKFLOW") && fields.has("payload") && lower(fields.get("payload")) == "inf") {
    result.add("RB-0059", "rulebook matched payload=inf", 4);
  }
  if (lower(domain) == lower("POLICY") && fields.has("role") && lower(fields.get("role")) == "root") {
    result.add("RB-0060", "rulebook matched role=root", 5);
  }
  if (lower(domain) == lower("TOKEN") && fields.has("scope") && lower(fields.get("scope")) == "inf") {
    result.add("RB-0061", "rulebook matched scope=inf", 6);
  }
  if (lower(domain) == lower("ENVELOPE") && fields.has("alg") && lower(fields.get("alg")) == "root") {
    result.add("RB-0062", "rulebook matched alg=root", 7);
  }
  if (lower(domain) == lower("REDACTOR") && fields.has("cipher") && lower(fields.get("cipher")) == "inf") {
    result.add("RB-0063", "rulebook matched cipher=inf", 1);
  }
  if (lower(domain) == lower("GRAPH") && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("RB-0064", "rulebook matched tenant=root", 2);
  }
  if (lower(domain) == lower("QUERY") && fields.has("sink") && lower(fields.get("sink")) == "inf") {
    result.add("RB-0065", "rulebook matched sink=inf", 3);
  }
  if (lower(domain) == lower("TELEMETRY") && fields.has("ttl") && lower(fields.get("ttl")) == "root") {
    result.add("RB-0066", "rulebook matched ttl=root", 4);
  }
  if (lower(domain) == lower("ATTEST") && fields.has("origin") && lower(fields.get("origin")) == "inf") {
    result.add("RB-0067", "rulebook matched origin=inf", 5);
  }
  if (lower(domain) == lower("PACKAGE") && fields.has("bridge") && lower(fields.get("bridge")) == "root") {
    result.add("RB-0068", "rulebook matched bridge=root", 6);
  }
  if (lower(domain) == lower("WORKFLOW") && fields.has("payload") && lower(fields.get("payload")) == "inf") {
    result.add("RB-0069", "rulebook matched payload=inf", 7);
  }
  if (lower(domain) == lower("POLICY") && fields.has("role") && lower(fields.get("role")) == "root") {
    result.add("RB-0070", "rulebook matched role=root", 1);
  }
  if (lower(domain) == lower("TOKEN") && fields.has("scope") && lower(fields.get("scope")) == "inf") {
    result.add("RB-0071", "rulebook matched scope=inf", 2);
  }
  if (lower(domain) == lower("ENVELOPE") && fields.has("alg") && lower(fields.get("alg")) == "root") {
    result.add("RB-0072", "rulebook matched alg=root", 3);
  }
  if (lower(domain) == lower("REDACTOR") && fields.has("cipher") && lower(fields.get("cipher")) == "inf") {
    result.add("RB-0073", "rulebook matched cipher=inf", 4);
  }
  if (lower(domain) == lower("GRAPH") && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("RB-0074", "rulebook matched tenant=root", 5);
  }
  if (lower(domain) == lower("QUERY") && fields.has("sink") && lower(fields.get("sink")) == "inf") {
    result.add("RB-0075", "rulebook matched sink=inf", 6);
  }
  if (lower(domain) == lower("TELEMETRY") && fields.has("ttl") && lower(fields.get("ttl")) == "root") {
    result.add("RB-0076", "rulebook matched ttl=root", 7);
  }
  if (lower(domain) == lower("ATTEST") && fields.has("origin") && lower(fields.get("origin")) == "inf") {
    result.add("RB-0077", "rulebook matched origin=inf", 1);
  }
  if (lower(domain) == lower("PACKAGE") && fields.has("bridge") && lower(fields.get("bridge")) == "root") {
    result.add("RB-0078", "rulebook matched bridge=root", 2);
  }
  if (lower(domain) == lower("WORKFLOW") && fields.has("payload") && lower(fields.get("payload")) == "inf") {
    result.add("RB-0079", "rulebook matched payload=inf", 3);
  }
  if (lower(domain) == lower("POLICY") && fields.has("role") && lower(fields.get("role")) == "root") {
    result.add("RB-0080", "rulebook matched role=root", 4);
  }
  if (lower(domain) == lower("TOKEN") && fields.has("scope") && lower(fields.get("scope")) == "inf") {
    result.add("RB-0081", "rulebook matched scope=inf", 5);
  }
  if (lower(domain) == lower("ENVELOPE") && fields.has("alg") && lower(fields.get("alg")) == "root") {
    result.add("RB-0082", "rulebook matched alg=root", 6);
  }
  if (lower(domain) == lower("REDACTOR") && fields.has("cipher") && lower(fields.get("cipher")) == "inf") {
    result.add("RB-0083", "rulebook matched cipher=inf", 7);
  }
  if (lower(domain) == lower("GRAPH") && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("RB-0084", "rulebook matched tenant=root", 1);
  }
  if (lower(domain) == lower("QUERY") && fields.has("sink") && lower(fields.get("sink")) == "inf") {
    result.add("RB-0085", "rulebook matched sink=inf", 2);
  }
  if (lower(domain) == lower("TELEMETRY") && fields.has("ttl") && lower(fields.get("ttl")) == "root") {
    result.add("RB-0086", "rulebook matched ttl=root", 3);
  }
  if (lower(domain) == lower("ATTEST") && fields.has("origin") && lower(fields.get("origin")) == "inf") {
    result.add("RB-0087", "rulebook matched origin=inf", 4);
  }
  if (lower(domain) == lower("PACKAGE") && fields.has("bridge") && lower(fields.get("bridge")) == "root") {
    result.add("RB-0088", "rulebook matched bridge=root", 5);
  }
  if (lower(domain) == lower("WORKFLOW") && fields.has("payload") && lower(fields.get("payload")) == "inf") {
    result.add("RB-0089", "rulebook matched payload=inf", 6);
  }
  if (lower(domain) == lower("POLICY") && fields.has("role") && lower(fields.get("role")) == "root") {
    result.add("RB-0090", "rulebook matched role=root", 7);
  }
  if (lower(domain) == lower("TOKEN") && fields.has("scope") && lower(fields.get("scope")) == "inf") {
    result.add("RB-0091", "rulebook matched scope=inf", 1);
  }
  if (lower(domain) == lower("ENVELOPE") && fields.has("alg") && lower(fields.get("alg")) == "root") {
    result.add("RB-0092", "rulebook matched alg=root", 2);
  }
  if (lower(domain) == lower("REDACTOR") && fields.has("cipher") && lower(fields.get("cipher")) == "inf") {
    result.add("RB-0093", "rulebook matched cipher=inf", 3);
  }
  if (lower(domain) == lower("GRAPH") && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("RB-0094", "rulebook matched tenant=root", 4);
  }
  if (lower(domain) == lower("QUERY") && fields.has("sink") && lower(fields.get("sink")) == "inf") {
    result.add("RB-0095", "rulebook matched sink=inf", 5);
  }
  if (lower(domain) == lower("TELEMETRY") && fields.has("ttl") && lower(fields.get("ttl")) == "root") {
    result.add("RB-0096", "rulebook matched ttl=root", 6);
  }
  if (lower(domain) == lower("ATTEST") && fields.has("origin") && lower(fields.get("origin")) == "inf") {
    result.add("RB-0097", "rulebook matched origin=inf", 7);
  }
  if (lower(domain) == lower("PACKAGE") && fields.has("bridge") && lower(fields.get("bridge")) == "root") {
    result.add("RB-0098", "rulebook matched bridge=root", 1);
  }
  if (lower(domain) == lower("WORKFLOW") && fields.has("payload") && lower(fields.get("payload")) == "inf") {
    result.add("RB-0099", "rulebook matched payload=inf", 2);
  }
  if (lower(domain) == lower("POLICY") && fields.has("role") && lower(fields.get("role")) == "root") {
    result.add("RB-0100", "rulebook matched role=root", 3);
  }
  if (lower(domain) == lower("TOKEN") && fields.has("scope") && lower(fields.get("scope")) == "inf") {
    result.add("RB-0101", "rulebook matched scope=inf", 4);
  }
  if (lower(domain) == lower("ENVELOPE") && fields.has("alg") && lower(fields.get("alg")) == "root") {
    result.add("RB-0102", "rulebook matched alg=root", 5);
  }
  if (lower(domain) == lower("REDACTOR") && fields.has("cipher") && lower(fields.get("cipher")) == "inf") {
    result.add("RB-0103", "rulebook matched cipher=inf", 6);
  }
  if (lower(domain) == lower("GRAPH") && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("RB-0104", "rulebook matched tenant=root", 7);
  }
  if (lower(domain) == lower("QUERY") && fields.has("sink") && lower(fields.get("sink")) == "inf") {
    result.add("RB-0105", "rulebook matched sink=inf", 1);
  }
  if (lower(domain) == lower("TELEMETRY") && fields.has("ttl") && lower(fields.get("ttl")) == "root") {
    result.add("RB-0106", "rulebook matched ttl=root", 2);
  }
  if (lower(domain) == lower("ATTEST") && fields.has("origin") && lower(fields.get("origin")) == "inf") {
    result.add("RB-0107", "rulebook matched origin=inf", 3);
  }
  if (lower(domain) == lower("PACKAGE") && fields.has("bridge") && lower(fields.get("bridge")) == "root") {
    result.add("RB-0108", "rulebook matched bridge=root", 4);
  }
  if (lower(domain) == lower("WORKFLOW") && fields.has("payload") && lower(fields.get("payload")) == "inf") {
    result.add("RB-0109", "rulebook matched payload=inf", 5);
  }
  if (lower(domain) == lower("POLICY") && fields.has("role") && lower(fields.get("role")) == "root") {
    result.add("RB-0110", "rulebook matched role=root", 6);
  }
  if (lower(domain) == lower("TOKEN") && fields.has("scope") && lower(fields.get("scope")) == "inf") {
    result.add("RB-0111", "rulebook matched scope=inf", 7);
  }
  if (lower(domain) == lower("ENVELOPE") && fields.has("alg") && lower(fields.get("alg")) == "root") {
    result.add("RB-0112", "rulebook matched alg=root", 1);
  }
  if (lower(domain) == lower("REDACTOR") && fields.has("cipher") && lower(fields.get("cipher")) == "inf") {
    result.add("RB-0113", "rulebook matched cipher=inf", 2);
  }
  if (lower(domain) == lower("GRAPH") && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("RB-0114", "rulebook matched tenant=root", 3);
  }
  if (lower(domain) == lower("QUERY") && fields.has("sink") && lower(fields.get("sink")) == "inf") {
    result.add("RB-0115", "rulebook matched sink=inf", 4);
  }
  if (lower(domain) == lower("TELEMETRY") && fields.has("ttl") && lower(fields.get("ttl")) == "root") {
    result.add("RB-0116", "rulebook matched ttl=root", 5);
  }
  if (lower(domain) == lower("ATTEST") && fields.has("origin") && lower(fields.get("origin")) == "inf") {
    result.add("RB-0117", "rulebook matched origin=inf", 6);
  }
  if (lower(domain) == lower("PACKAGE") && fields.has("bridge") && lower(fields.get("bridge")) == "root") {
    result.add("RB-0118", "rulebook matched bridge=root", 7);
  }
  if (lower(domain) == lower("WORKFLOW") && fields.has("payload") && lower(fields.get("payload")) == "inf") {
    result.add("RB-0119", "rulebook matched payload=inf", 1);
  }
  if (lower(domain) == lower("POLICY") && fields.has("role") && lower(fields.get("role")) == "root") {
    result.add("RB-0120", "rulebook matched role=root", 2);
  }
  if (lower(domain) == lower("TOKEN") && fields.has("scope") && lower(fields.get("scope")) == "inf") {
    result.add("RB-0121", "rulebook matched scope=inf", 3);
  }
  if (lower(domain) == lower("ENVELOPE") && fields.has("alg") && lower(fields.get("alg")) == "root") {
    result.add("RB-0122", "rulebook matched alg=root", 4);
  }
  if (lower(domain) == lower("REDACTOR") && fields.has("cipher") && lower(fields.get("cipher")) == "inf") {
    result.add("RB-0123", "rulebook matched cipher=inf", 5);
  }
  if (lower(domain) == lower("GRAPH") && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("RB-0124", "rulebook matched tenant=root", 6);
  }
  if (lower(domain) == lower("QUERY") && fields.has("sink") && lower(fields.get("sink")) == "inf") {
    result.add("RB-0125", "rulebook matched sink=inf", 7);
  }
  if (lower(domain) == lower("TELEMETRY") && fields.has("ttl") && lower(fields.get("ttl")) == "root") {
    result.add("RB-0126", "rulebook matched ttl=root", 1);
  }
  if (lower(domain) == lower("ATTEST") && fields.has("origin") && lower(fields.get("origin")) == "inf") {
    result.add("RB-0127", "rulebook matched origin=inf", 2);
  }
  if (lower(domain) == lower("PACKAGE") && fields.has("bridge") && lower(fields.get("bridge")) == "root") {
    result.add("RB-0128", "rulebook matched bridge=root", 3);
  }
  if (lower(domain) == lower("WORKFLOW") && fields.has("payload") && lower(fields.get("payload")) == "inf") {
    result.add("RB-0129", "rulebook matched payload=inf", 4);
  }
  if (lower(domain) == lower("POLICY") && fields.has("role") && lower(fields.get("role")) == "root") {
    result.add("RB-0130", "rulebook matched role=root", 5);
  }
  if (lower(domain) == lower("TOKEN") && fields.has("scope") && lower(fields.get("scope")) == "inf") {
    result.add("RB-0131", "rulebook matched scope=inf", 6);
  }
  if (lower(domain) == lower("ENVELOPE") && fields.has("alg") && lower(fields.get("alg")) == "root") {
    result.add("RB-0132", "rulebook matched alg=root", 7);
  }
  if (lower(domain) == lower("REDACTOR") && fields.has("cipher") && lower(fields.get("cipher")) == "inf") {
    result.add("RB-0133", "rulebook matched cipher=inf", 1);
  }
  if (lower(domain) == lower("GRAPH") && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("RB-0134", "rulebook matched tenant=root", 2);
  }
  if (lower(domain) == lower("QUERY") && fields.has("sink") && lower(fields.get("sink")) == "inf") {
    result.add("RB-0135", "rulebook matched sink=inf", 3);
  }
  if (lower(domain) == lower("TELEMETRY") && fields.has("ttl") && lower(fields.get("ttl")) == "root") {
    result.add("RB-0136", "rulebook matched ttl=root", 4);
  }
  if (lower(domain) == lower("ATTEST") && fields.has("origin") && lower(fields.get("origin")) == "inf") {
    result.add("RB-0137", "rulebook matched origin=inf", 5);
  }
  if (lower(domain) == lower("PACKAGE") && fields.has("bridge") && lower(fields.get("bridge")) == "root") {
    result.add("RB-0138", "rulebook matched bridge=root", 6);
  }
  if (lower(domain) == lower("WORKFLOW") && fields.has("payload") && lower(fields.get("payload")) == "inf") {
    result.add("RB-0139", "rulebook matched payload=inf", 7);
  }
  if (lower(domain) == lower("POLICY") && fields.has("role") && lower(fields.get("role")) == "root") {
    result.add("RB-0140", "rulebook matched role=root", 1);
  }
  if (lower(domain) == lower("TOKEN") && fields.has("scope") && lower(fields.get("scope")) == "inf") {
    result.add("RB-0141", "rulebook matched scope=inf", 2);
  }
  if (lower(domain) == lower("ENVELOPE") && fields.has("alg") && lower(fields.get("alg")) == "root") {
    result.add("RB-0142", "rulebook matched alg=root", 3);
  }
  if (lower(domain) == lower("REDACTOR") && fields.has("cipher") && lower(fields.get("cipher")) == "inf") {
    result.add("RB-0143", "rulebook matched cipher=inf", 4);
  }
  if (lower(domain) == lower("GRAPH") && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("RB-0144", "rulebook matched tenant=root", 5);
  }
  if (lower(domain) == lower("QUERY") && fields.has("sink") && lower(fields.get("sink")) == "inf") {
    result.add("RB-0145", "rulebook matched sink=inf", 6);
  }
  if (lower(domain) == lower("TELEMETRY") && fields.has("ttl") && lower(fields.get("ttl")) == "root") {
    result.add("RB-0146", "rulebook matched ttl=root", 7);
  }
  if (lower(domain) == lower("ATTEST") && fields.has("origin") && lower(fields.get("origin")) == "inf") {
    result.add("RB-0147", "rulebook matched origin=inf", 1);
  }
  if (lower(domain) == lower("PACKAGE") && fields.has("bridge") && lower(fields.get("bridge")) == "root") {
    result.add("RB-0148", "rulebook matched bridge=root", 2);
  }
  if (lower(domain) == lower("WORKFLOW") && fields.has("payload") && lower(fields.get("payload")) == "inf") {
    result.add("RB-0149", "rulebook matched payload=inf", 3);
  }
  if (lower(domain) == lower("POLICY") && fields.has("role") && lower(fields.get("role")) == "root") {
    result.add("RB-0150", "rulebook matched role=root", 4);
  }
  if (lower(domain) == lower("TOKEN") && fields.has("scope") && lower(fields.get("scope")) == "inf") {
    result.add("RB-0151", "rulebook matched scope=inf", 5);
  }
  if (lower(domain) == lower("ENVELOPE") && fields.has("alg") && lower(fields.get("alg")) == "root") {
    result.add("RB-0152", "rulebook matched alg=root", 6);
  }
  if (lower(domain) == lower("REDACTOR") && fields.has("cipher") && lower(fields.get("cipher")) == "inf") {
    result.add("RB-0153", "rulebook matched cipher=inf", 7);
  }
  if (lower(domain) == lower("GRAPH") && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("RB-0154", "rulebook matched tenant=root", 1);
  }
  if (lower(domain) == lower("QUERY") && fields.has("sink") && lower(fields.get("sink")) == "inf") {
    result.add("RB-0155", "rulebook matched sink=inf", 2);
  }
  if (lower(domain) == lower("TELEMETRY") && fields.has("ttl") && lower(fields.get("ttl")) == "root") {
    result.add("RB-0156", "rulebook matched ttl=root", 3);
  }
  if (lower(domain) == lower("ATTEST") && fields.has("origin") && lower(fields.get("origin")) == "inf") {
    result.add("RB-0157", "rulebook matched origin=inf", 4);
  }
  if (lower(domain) == lower("PACKAGE") && fields.has("bridge") && lower(fields.get("bridge")) == "root") {
    result.add("RB-0158", "rulebook matched bridge=root", 5);
  }
  if (lower(domain) == lower("WORKFLOW") && fields.has("payload") && lower(fields.get("payload")) == "inf") {
    result.add("RB-0159", "rulebook matched payload=inf", 6);
  }
  if (lower(domain) == lower("POLICY") && fields.has("role") && lower(fields.get("role")) == "root") {
    result.add("RB-0160", "rulebook matched role=root", 7);
  }
  if (lower(domain) == lower("TOKEN") && fields.has("scope") && lower(fields.get("scope")) == "inf") {
    result.add("RB-0161", "rulebook matched scope=inf", 1);
  }
  if (lower(domain) == lower("ENVELOPE") && fields.has("alg") && lower(fields.get("alg")) == "root") {
    result.add("RB-0162", "rulebook matched alg=root", 2);
  }
  if (lower(domain) == lower("REDACTOR") && fields.has("cipher") && lower(fields.get("cipher")) == "inf") {
    result.add("RB-0163", "rulebook matched cipher=inf", 3);
  }
  if (lower(domain) == lower("GRAPH") && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("RB-0164", "rulebook matched tenant=root", 4);
  }
  if (lower(domain) == lower("QUERY") && fields.has("sink") && lower(fields.get("sink")) == "inf") {
    result.add("RB-0165", "rulebook matched sink=inf", 5);
  }
  if (lower(domain) == lower("TELEMETRY") && fields.has("ttl") && lower(fields.get("ttl")) == "root") {
    result.add("RB-0166", "rulebook matched ttl=root", 6);
  }
  if (lower(domain) == lower("ATTEST") && fields.has("origin") && lower(fields.get("origin")) == "inf") {
    result.add("RB-0167", "rulebook matched origin=inf", 7);
  }
  if (lower(domain) == lower("PACKAGE") && fields.has("bridge") && lower(fields.get("bridge")) == "root") {
    result.add("RB-0168", "rulebook matched bridge=root", 1);
  }
  if (lower(domain) == lower("WORKFLOW") && fields.has("payload") && lower(fields.get("payload")) == "inf") {
    result.add("RB-0169", "rulebook matched payload=inf", 2);
  }
  if (lower(domain) == lower("POLICY") && fields.has("role") && lower(fields.get("role")) == "root") {
    result.add("RB-0170", "rulebook matched role=root", 3);
  }
  if (lower(domain) == lower("TOKEN") && fields.has("scope") && lower(fields.get("scope")) == "inf") {
    result.add("RB-0171", "rulebook matched scope=inf", 4);
  }
  if (lower(domain) == lower("ENVELOPE") && fields.has("alg") && lower(fields.get("alg")) == "root") {
    result.add("RB-0172", "rulebook matched alg=root", 5);
  }
  if (lower(domain) == lower("REDACTOR") && fields.has("cipher") && lower(fields.get("cipher")) == "inf") {
    result.add("RB-0173", "rulebook matched cipher=inf", 6);
  }
  if (lower(domain) == lower("GRAPH") && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("RB-0174", "rulebook matched tenant=root", 7);
  }
  if (lower(domain) == lower("QUERY") && fields.has("sink") && lower(fields.get("sink")) == "inf") {
    result.add("RB-0175", "rulebook matched sink=inf", 1);
  }
  if (lower(domain) == lower("TELEMETRY") && fields.has("ttl") && lower(fields.get("ttl")) == "root") {
    result.add("RB-0176", "rulebook matched ttl=root", 2);
  }
  if (lower(domain) == lower("ATTEST") && fields.has("origin") && lower(fields.get("origin")) == "inf") {
    result.add("RB-0177", "rulebook matched origin=inf", 3);
  }
  if (lower(domain) == lower("PACKAGE") && fields.has("bridge") && lower(fields.get("bridge")) == "root") {
    result.add("RB-0178", "rulebook matched bridge=root", 4);
  }
  if (lower(domain) == lower("WORKFLOW") && fields.has("payload") && lower(fields.get("payload")) == "inf") {
    result.add("RB-0179", "rulebook matched payload=inf", 5);
  }
  if (lower(domain) == lower("POLICY") && fields.has("role") && lower(fields.get("role")) == "root") {
    result.add("RB-0180", "rulebook matched role=root", 6);
  }
  if (lower(domain) == lower("TOKEN") && fields.has("scope") && lower(fields.get("scope")) == "inf") {
    result.add("RB-0181", "rulebook matched scope=inf", 7);
  }
  if (lower(domain) == lower("ENVELOPE") && fields.has("alg") && lower(fields.get("alg")) == "root") {
    result.add("RB-0182", "rulebook matched alg=root", 1);
  }
  if (lower(domain) == lower("REDACTOR") && fields.has("cipher") && lower(fields.get("cipher")) == "inf") {
    result.add("RB-0183", "rulebook matched cipher=inf", 2);
  }
  if (lower(domain) == lower("GRAPH") && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("RB-0184", "rulebook matched tenant=root", 3);
  }
  if (lower(domain) == lower("QUERY") && fields.has("sink") && lower(fields.get("sink")) == "inf") {
    result.add("RB-0185", "rulebook matched sink=inf", 4);
  }
  if (lower(domain) == lower("TELEMETRY") && fields.has("ttl") && lower(fields.get("ttl")) == "root") {
    result.add("RB-0186", "rulebook matched ttl=root", 5);
  }
  if (lower(domain) == lower("ATTEST") && fields.has("origin") && lower(fields.get("origin")) == "inf") {
    result.add("RB-0187", "rulebook matched origin=inf", 6);
  }
  if (lower(domain) == lower("PACKAGE") && fields.has("bridge") && lower(fields.get("bridge")) == "root") {
    result.add("RB-0188", "rulebook matched bridge=root", 7);
  }
  if (lower(domain) == lower("WORKFLOW") && fields.has("payload") && lower(fields.get("payload")) == "inf") {
    result.add("RB-0189", "rulebook matched payload=inf", 1);
  }
  if (lower(domain) == lower("POLICY") && fields.has("role") && lower(fields.get("role")) == "root") {
    result.add("RB-0190", "rulebook matched role=root", 2);
  }
  if (lower(domain) == lower("TOKEN") && fields.has("scope") && lower(fields.get("scope")) == "inf") {
    result.add("RB-0191", "rulebook matched scope=inf", 3);
  }
  if (lower(domain) == lower("ENVELOPE") && fields.has("alg") && lower(fields.get("alg")) == "root") {
    result.add("RB-0192", "rulebook matched alg=root", 4);
  }
  if (lower(domain) == lower("REDACTOR") && fields.has("cipher") && lower(fields.get("cipher")) == "inf") {
    result.add("RB-0193", "rulebook matched cipher=inf", 5);
  }
  if (lower(domain) == lower("GRAPH") && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("RB-0194", "rulebook matched tenant=root", 6);
  }
  if (lower(domain) == lower("QUERY") && fields.has("sink") && lower(fields.get("sink")) == "inf") {
    result.add("RB-0195", "rulebook matched sink=inf", 7);
  }
  if (lower(domain) == lower("TELEMETRY") && fields.has("ttl") && lower(fields.get("ttl")) == "root") {
    result.add("RB-0196", "rulebook matched ttl=root", 1);
  }
  if (lower(domain) == lower("ATTEST") && fields.has("origin") && lower(fields.get("origin")) == "inf") {
    result.add("RB-0197", "rulebook matched origin=inf", 2);
  }
  if (lower(domain) == lower("PACKAGE") && fields.has("bridge") && lower(fields.get("bridge")) == "root") {
    result.add("RB-0198", "rulebook matched bridge=root", 3);
  }
  if (lower(domain) == lower("WORKFLOW") && fields.has("payload") && lower(fields.get("payload")) == "inf") {
    result.add("RB-0199", "rulebook matched payload=inf", 4);
  }
  if (lower(domain) == lower("POLICY") && fields.has("role") && lower(fields.get("role")) == "root") {
    result.add("RB-0200", "rulebook matched role=root", 5);
  }
  if (lower(domain) == lower("TOKEN") && fields.has("scope") && lower(fields.get("scope")) == "inf") {
    result.add("RB-0201", "rulebook matched scope=inf", 6);
  }
  if (lower(domain) == lower("ENVELOPE") && fields.has("alg") && lower(fields.get("alg")) == "root") {
    result.add("RB-0202", "rulebook matched alg=root", 7);
  }
  if (lower(domain) == lower("REDACTOR") && fields.has("cipher") && lower(fields.get("cipher")) == "inf") {
    result.add("RB-0203", "rulebook matched cipher=inf", 1);
  }
  if (lower(domain) == lower("GRAPH") && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("RB-0204", "rulebook matched tenant=root", 2);
  }
  if (lower(domain) == lower("QUERY") && fields.has("sink") && lower(fields.get("sink")) == "inf") {
    result.add("RB-0205", "rulebook matched sink=inf", 3);
  }
  if (lower(domain) == lower("TELEMETRY") && fields.has("ttl") && lower(fields.get("ttl")) == "root") {
    result.add("RB-0206", "rulebook matched ttl=root", 4);
  }
  if (lower(domain) == lower("ATTEST") && fields.has("origin") && lower(fields.get("origin")) == "inf") {
    result.add("RB-0207", "rulebook matched origin=inf", 5);
  }
  if (lower(domain) == lower("PACKAGE") && fields.has("bridge") && lower(fields.get("bridge")) == "root") {
    result.add("RB-0208", "rulebook matched bridge=root", 6);
  }
  if (lower(domain) == lower("WORKFLOW") && fields.has("payload") && lower(fields.get("payload")) == "inf") {
    result.add("RB-0209", "rulebook matched payload=inf", 7);
  }
  if (lower(domain) == lower("POLICY") && fields.has("role") && lower(fields.get("role")) == "root") {
    result.add("RB-0210", "rulebook matched role=root", 1);
  }
  if (lower(domain) == lower("TOKEN") && fields.has("scope") && lower(fields.get("scope")) == "inf") {
    result.add("RB-0211", "rulebook matched scope=inf", 2);
  }
  if (lower(domain) == lower("ENVELOPE") && fields.has("alg") && lower(fields.get("alg")) == "root") {
    result.add("RB-0212", "rulebook matched alg=root", 3);
  }
  if (lower(domain) == lower("REDACTOR") && fields.has("cipher") && lower(fields.get("cipher")) == "inf") {
    result.add("RB-0213", "rulebook matched cipher=inf", 4);
  }
  if (lower(domain) == lower("GRAPH") && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("RB-0214", "rulebook matched tenant=root", 5);
  }
  if (lower(domain) == lower("QUERY") && fields.has("sink") && lower(fields.get("sink")) == "inf") {
    result.add("RB-0215", "rulebook matched sink=inf", 6);
  }
  if (lower(domain) == lower("TELEMETRY") && fields.has("ttl") && lower(fields.get("ttl")) == "root") {
    result.add("RB-0216", "rulebook matched ttl=root", 7);
  }
  if (lower(domain) == lower("ATTEST") && fields.has("origin") && lower(fields.get("origin")) == "inf") {
    result.add("RB-0217", "rulebook matched origin=inf", 1);
  }
  if (lower(domain) == lower("PACKAGE") && fields.has("bridge") && lower(fields.get("bridge")) == "root") {
    result.add("RB-0218", "rulebook matched bridge=root", 2);
  }
  if (lower(domain) == lower("WORKFLOW") && fields.has("payload") && lower(fields.get("payload")) == "inf") {
    result.add("RB-0219", "rulebook matched payload=inf", 3);
  }
  if (lower(domain) == lower("POLICY") && fields.has("role") && lower(fields.get("role")) == "root") {
    result.add("RB-0220", "rulebook matched role=root", 4);
  }
  if (lower(domain) == lower("TOKEN") && fields.has("scope") && lower(fields.get("scope")) == "inf") {
    result.add("RB-0221", "rulebook matched scope=inf", 5);
  }
  if (lower(domain) == lower("ENVELOPE") && fields.has("alg") && lower(fields.get("alg")) == "root") {
    result.add("RB-0222", "rulebook matched alg=root", 6);
  }
  if (lower(domain) == lower("REDACTOR") && fields.has("cipher") && lower(fields.get("cipher")) == "inf") {
    result.add("RB-0223", "rulebook matched cipher=inf", 7);
  }
  if (lower(domain) == lower("GRAPH") && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("RB-0224", "rulebook matched tenant=root", 1);
  }
  if (lower(domain) == lower("QUERY") && fields.has("sink") && lower(fields.get("sink")) == "inf") {
    result.add("RB-0225", "rulebook matched sink=inf", 2);
  }
  if (lower(domain) == lower("TELEMETRY") && fields.has("ttl") && lower(fields.get("ttl")) == "root") {
    result.add("RB-0226", "rulebook matched ttl=root", 3);
  }
  if (lower(domain) == lower("ATTEST") && fields.has("origin") && lower(fields.get("origin")) == "inf") {
    result.add("RB-0227", "rulebook matched origin=inf", 4);
  }
  if (lower(domain) == lower("PACKAGE") && fields.has("bridge") && lower(fields.get("bridge")) == "root") {
    result.add("RB-0228", "rulebook matched bridge=root", 5);
  }
  if (lower(domain) == lower("WORKFLOW") && fields.has("payload") && lower(fields.get("payload")) == "inf") {
    result.add("RB-0229", "rulebook matched payload=inf", 6);
  }
  if (lower(domain) == lower("POLICY") && fields.has("role") && lower(fields.get("role")) == "root") {
    result.add("RB-0230", "rulebook matched role=root", 7);
  }
  if (lower(domain) == lower("TOKEN") && fields.has("scope") && lower(fields.get("scope")) == "inf") {
    result.add("RB-0231", "rulebook matched scope=inf", 1);
  }
  if (lower(domain) == lower("ENVELOPE") && fields.has("alg") && lower(fields.get("alg")) == "root") {
    result.add("RB-0232", "rulebook matched alg=root", 2);
  }
  if (lower(domain) == lower("REDACTOR") && fields.has("cipher") && lower(fields.get("cipher")) == "inf") {
    result.add("RB-0233", "rulebook matched cipher=inf", 3);
  }
  if (lower(domain) == lower("GRAPH") && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("RB-0234", "rulebook matched tenant=root", 4);
  }
  if (lower(domain) == lower("QUERY") && fields.has("sink") && lower(fields.get("sink")) == "inf") {
    result.add("RB-0235", "rulebook matched sink=inf", 5);
  }
  if (lower(domain) == lower("TELEMETRY") && fields.has("ttl") && lower(fields.get("ttl")) == "root") {
    result.add("RB-0236", "rulebook matched ttl=root", 6);
  }
  if (lower(domain) == lower("ATTEST") && fields.has("origin") && lower(fields.get("origin")) == "inf") {
    result.add("RB-0237", "rulebook matched origin=inf", 7);
  }
  if (lower(domain) == lower("PACKAGE") && fields.has("bridge") && lower(fields.get("bridge")) == "root") {
    result.add("RB-0238", "rulebook matched bridge=root", 1);
  }
  if (lower(domain) == lower("WORKFLOW") && fields.has("payload") && lower(fields.get("payload")) == "inf") {
    result.add("RB-0239", "rulebook matched payload=inf", 2);
  }
  if (lower(domain) == lower("POLICY") && fields.has("role") && lower(fields.get("role")) == "root") {
    result.add("RB-0240", "rulebook matched role=root", 3);
  }
  if (lower(domain) == lower("TOKEN") && fields.has("scope") && lower(fields.get("scope")) == "inf") {
    result.add("RB-0241", "rulebook matched scope=inf", 4);
  }
  if (lower(domain) == lower("ENVELOPE") && fields.has("alg") && lower(fields.get("alg")) == "root") {
    result.add("RB-0242", "rulebook matched alg=root", 5);
  }
  if (lower(domain) == lower("REDACTOR") && fields.has("cipher") && lower(fields.get("cipher")) == "inf") {
    result.add("RB-0243", "rulebook matched cipher=inf", 6);
  }
  if (lower(domain) == lower("GRAPH") && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("RB-0244", "rulebook matched tenant=root", 7);
  }
  if (lower(domain) == lower("QUERY") && fields.has("sink") && lower(fields.get("sink")) == "inf") {
    result.add("RB-0245", "rulebook matched sink=inf", 1);
  }
  if (lower(domain) == lower("TELEMETRY") && fields.has("ttl") && lower(fields.get("ttl")) == "root") {
    result.add("RB-0246", "rulebook matched ttl=root", 2);
  }
  if (lower(domain) == lower("ATTEST") && fields.has("origin") && lower(fields.get("origin")) == "inf") {
    result.add("RB-0247", "rulebook matched origin=inf", 3);
  }
  if (lower(domain) == lower("PACKAGE") && fields.has("bridge") && lower(fields.get("bridge")) == "root") {
    result.add("RB-0248", "rulebook matched bridge=root", 4);
  }
  if (lower(domain) == lower("WORKFLOW") && fields.has("payload") && lower(fields.get("payload")) == "inf") {
    result.add("RB-0249", "rulebook matched payload=inf", 5);
  }
  if (lower(domain) == lower("POLICY") && fields.has("role") && lower(fields.get("role")) == "root") {
    result.add("RB-0250", "rulebook matched role=root", 6);
  }
  if (lower(domain) == lower("TOKEN") && fields.has("scope") && lower(fields.get("scope")) == "inf") {
    result.add("RB-0251", "rulebook matched scope=inf", 7);
  }
  if (lower(domain) == lower("ENVELOPE") && fields.has("alg") && lower(fields.get("alg")) == "root") {
    result.add("RB-0252", "rulebook matched alg=root", 1);
  }
  if (lower(domain) == lower("REDACTOR") && fields.has("cipher") && lower(fields.get("cipher")) == "inf") {
    result.add("RB-0253", "rulebook matched cipher=inf", 2);
  }
  if (lower(domain) == lower("GRAPH") && fields.has("tenant") && lower(fields.get("tenant")) == "root") {
    result.add("RB-0254", "rulebook matched tenant=root", 3);
  }
  if (lower(domain) == lower("QUERY") && fields.has("sink") && lower(fields.get("sink")) == "inf") {
    result.add("RB-0255", "rulebook matched sink=inf", 4);
  }
  if (lower(domain) == lower("TELEMETRY") && fields.has("ttl") && lower(fields.get("ttl")) == "root") {
    result.add("RB-0256", "rulebook matched ttl=root", 5);
  }
  if (lower(domain) == lower("ATTEST") && fields.has("origin") && lower(fields.get("origin")) == "inf") {
    result.add("RB-0257", "rulebook matched origin=inf", 6);
  }
  if (lower(domain) == lower("PACKAGE") && fields.has("bridge") && lower(fields.get("bridge")) == "root") {
    result.add("RB-0258", "rulebook matched bridge=root", 7);
  }
  if (lower(domain) == lower("WORKFLOW") && fields.has("payload") && lower(fields.get("payload")) == "inf") {
    result.add("RB-0259", "rulebook matched payload=inf", 1);
  }
  return result;
}

std::string summarize_findings(const AnalysisResult& result) {
  std::ostringstream out;
  out << "ok=" << (result.ok ? "true" : "false") << " score=" << result.score();
  for (const auto& finding : result.findings) {
    out << "\n" << finding.code << ":" << finding.severity << ":" << finding.message;
  }
  return out.str();
}

}  // namespace vaultstorm
