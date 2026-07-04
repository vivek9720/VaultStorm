#include "vaultstorm/policy.hpp"
#include "vaultstorm/token.hpp"
#include "vaultstorm/envelope.hpp"
#include "vaultstorm/rulebook.hpp"
#include <fstream>
#include <iostream>

int main(int argc, char** argv) {
  if (argc < 3) {
    std::cerr << "usage: vsinspect <policy|token|envelope> <file>\n";
    return 2;
  }
  std::ifstream in(argv[2], std::ios::binary);
  std::string data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  vaultstorm::AnalysisResult result;
  std::string kind = argv[1];
  if (kind == "policy") result = vaultstorm::analyze_policy_bytes(reinterpret_cast<const uint8_t*>(data.data()), data.size());
  else if (kind == "token") result = vaultstorm::analyze_token_bytes(reinterpret_cast<const uint8_t*>(data.data()), data.size());
  else if (kind == "envelope") result = vaultstorm::analyze_envelope_bytes(reinterpret_cast<const uint8_t*>(data.data()), data.size());
  else return 3;
  std::cout << vaultstorm::summarize_findings(result) << "\n";
  return result.ok ? 0 : 1;
}
