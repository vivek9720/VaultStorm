#ifndef VAULTSTORM_RULEBOOK_HPP
#define VAULTSTORM_RULEBOOK_HPP

#include "vaultstorm/normalizer.hpp"
#include "vaultstorm/result.hpp"
#include <string>

namespace vaultstorm {

AnalysisResult apply_rulebook(const FieldMap& fields, const std::string& domain);
std::string summarize_findings(const AnalysisResult& result);

}  // namespace vaultstorm

#endif
