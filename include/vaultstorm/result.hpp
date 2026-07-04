#ifndef VAULTSTORM_RESULT_HPP
#define VAULTSTORM_RESULT_HPP

#include <string>
#include <vector>

namespace vaultstorm {

struct Finding {
  std::string code;
  std::string message;
  int severity = 0;
};

struct AnalysisResult {
  bool ok = true;
  std::vector<Finding> findings;
  std::vector<std::string> tags;
  void add(std::string code, std::string message, int severity);
  bool has_code(const std::string& code) const;
  int score() const;
};

void crash_if(bool condition, const char* message);

}  // namespace vaultstorm

#endif
