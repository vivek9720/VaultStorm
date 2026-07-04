#include "vaultstorm/policy.hpp"
#include "vaultstorm/token.hpp"
#include "vaultstorm/envelope.hpp"
#include <cassert>
#include <cstdint>
#include <string>

int main() {
  std::string p = "type=POLICY\nrole=reader\nscope=logs\nttl=30\n";
  auto pr = vaultstorm::analyze_policy_bytes(reinterpret_cast<const uint8_t*>(p.data()), p.size());
  assert(pr.ok || !pr.findings.empty());
  std::string t = "type=TOKEN\nalg=RS256\nkid=service\naud=metrics\n";
  auto tr = vaultstorm::analyze_token_bytes(reinterpret_cast<const uint8_t*>(t.data()), t.size());
  assert(tr.ok || !tr.findings.empty());
  std::string e = "type=ENVELOPE\ncipher=aes-gcm\nwrap=kms\naad=tenant:blue\n";
  auto er = vaultstorm::analyze_envelope_bytes(reinterpret_cast<const uint8_t*>(e.data()), e.size());
  assert(er.ok || !er.findings.empty());
  return 0;
}
