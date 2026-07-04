#ifndef VAULTSTORM_CATALOG_HPP
#define VAULTSTORM_CATALOG_HPP

#include <string>
#include <vector>

namespace vaultstorm {

struct CatalogRule {
  std::string id;
  std::string domain;
  std::string key;
  std::string value;
  int severity;
  std::string message;
};

const std::vector<CatalogRule>& built_in_catalog();
std::vector<CatalogRule> catalog_for_domain(const std::string& domain);

}  // namespace vaultstorm

#endif
