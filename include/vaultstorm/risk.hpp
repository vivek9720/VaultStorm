#ifndef VAULTSTORM_RISK_HPP
#define VAULTSTORM_RISK_HPP

#include "vaultstorm/normalizer.hpp"
#include <string>

namespace vaultstorm {

int score_security_record(const FieldMap& fields, const std::string& domain);
bool is_privileged_identity(const std::string& value);
bool is_weak_crypto_name(const std::string& value);
bool is_public_boundary(const std::string& value);

}  // namespace vaultstorm

#endif
