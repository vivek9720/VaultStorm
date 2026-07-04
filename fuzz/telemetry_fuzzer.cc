#include "vaultstorm/telemetry.hpp"
#include "vaultstorm/rulebook.hpp"
#include <cstdint>
#include <cstddef>
#include <iostream>
#include <iterator>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  auto result = vaultstorm::analyze_telemetry_bytes(data, size);
  (void)result;
  return 0;
}

#ifdef VAULTSTORM_STANDALONE
int main() {
  std::string input((std::istreambuf_iterator<char>(std::cin)), std::istreambuf_iterator<char>());
  return LLVMFuzzerTestOneInput(reinterpret_cast<const uint8_t*>(input.data()), input.size());
}
#endif
