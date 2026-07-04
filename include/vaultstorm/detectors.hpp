#ifndef VAULTSTORM_DETECTORS_HPP
#define VAULTSTORM_DETECTORS_HPP

#include "vaultstorm/normalizer.hpp"
#include "vaultstorm/result.hpp"
#include <string>

namespace vaultstorm {

AnalysisResult run_auto_detectors(const FieldMap& fields, const std::string& domain);

}  // namespace vaultstorm

#endif
