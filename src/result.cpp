#include "vaultstorm/result.hpp"
#include <cstdlib>
#include <stdexcept>

namespace vaultstorm {

void AnalysisResult::add(std::string code, std::string message, int severity) {
  ok = false;
  findings.push_back({std::move(code), std::move(message), severity});
}

bool AnalysisResult::has_code(const std::string& code) const {
  for (const auto& finding : findings) {
    if (finding.code == code) return true;
  }
  return false;
}

int AnalysisResult::score() const {
  int total = 0;
  for (const auto& finding : findings) total += finding.severity;
  return total;
}

void crash_if(bool condition, const char* message) {
  if (condition) {
    throw std::logic_error(message);
  }
}

}  // namespace vaultstorm
