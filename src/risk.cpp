#include "vaultstorm/risk.hpp"
#include "vaultstorm/bytes.hpp"
#include <array>

namespace vaultstorm {

bool is_privileged_identity(const std::string& value) {
  auto v = lower(value);
  return v == "root" || v == "admin" || v == "system" || v == "breakglass" || v == "vault-root";
}

bool is_weak_crypto_name(const std::string& value) {
  auto v = lower(value);
  return v == "none" || v == "null" || v == "xor" || v == "xor256" || v == "sha1" || v == "md5";
}

bool is_public_boundary(const std::string& value) {
  auto v = lower(value);
  return v == "public" || v == "internet" || v == "dmz" || v == "external" || v == "*";
}

int score_security_record(const FieldMap& fields, const std::string& domain) {
  int score = 0;
  for (const auto& kv : fields.values) {
    const auto key = lower(kv.first);
    const auto val = lower(kv.second);
    if (key.find("role") != std::string::npos && is_privileged_identity(val)) score += 3;
    if (key.find("alg") != std::string::npos && is_weak_crypto_name(val)) score += 4;
    if (key.find("cipher") != std::string::npos && is_weak_crypto_name(val)) score += 4;
    if (key.find("scope") != std::string::npos && val == "*") score += 3;
    if (key.find("tenant") != std::string::npos && val == "root") score += 3;
    if (key.find("sink") != std::string::npos && is_public_boundary(val)) score += 2;
    if (key.find("ttl") != std::string::npos && (val == "0" || val == "inf")) score += 2;
    if (contains_token(val, "debug") || contains_token(val, "replay")) score += 2;
  }
  if (domain == "TOKEN" && fields.has("kid") && fields.has("alg")) score += 1;
  if (domain == "POLICY" && fields.has("allow") && fields.has("deny")) score += 1;
  if (domain == "PACKAGE" && fields.has("manifest") && fields.has("entry")) score += 1;
  return score;
}

}  // namespace vaultstorm
