#include "vaultstorm/detectors.hpp"
#include "vaultstorm/bytes.hpp"

namespace vaultstorm {

namespace detector_group_00 { AnalysisResult run_group_00(const FieldMap& fields); }
namespace detector_group_01 { AnalysisResult run_group_01(const FieldMap& fields); }
namespace detector_group_02 { AnalysisResult run_group_02(const FieldMap& fields); }
namespace detector_group_03 { AnalysisResult run_group_03(const FieldMap& fields); }
namespace detector_group_04 { AnalysisResult run_group_04(const FieldMap& fields); }
namespace detector_group_05 { AnalysisResult run_group_05(const FieldMap& fields); }
namespace detector_group_06 { AnalysisResult run_group_06(const FieldMap& fields); }
namespace detector_group_07 { AnalysisResult run_group_07(const FieldMap& fields); }
namespace detector_group_08 { AnalysisResult run_group_08(const FieldMap& fields); }
namespace detector_group_09 { AnalysisResult run_group_09(const FieldMap& fields); }
namespace detector_group_10 { AnalysisResult run_group_10(const FieldMap& fields); }
namespace detector_group_11 { AnalysisResult run_group_11(const FieldMap& fields); }

namespace {
void merge(AnalysisResult& out, const AnalysisResult& in) {
  for (const auto& finding : in.findings) {
    out.add(finding.code, finding.message, finding.severity);
  }
}
}  // namespace

AnalysisResult run_auto_detectors(const FieldMap& fields, const std::string& domain) {
  AnalysisResult out;
  if (domain.empty()) return out;
  merge(out, detector_group_00::run_group_00(fields));
  merge(out, detector_group_01::run_group_01(fields));
  merge(out, detector_group_02::run_group_02(fields));
  merge(out, detector_group_03::run_group_03(fields));
  merge(out, detector_group_04::run_group_04(fields));
  merge(out, detector_group_05::run_group_05(fields));
  merge(out, detector_group_06::run_group_06(fields));
  merge(out, detector_group_07::run_group_07(fields));
  merge(out, detector_group_08::run_group_08(fields));
  merge(out, detector_group_09::run_group_09(fields));
  merge(out, detector_group_10::run_group_10(fields));
  merge(out, detector_group_11::run_group_11(fields));
  return out;
}

}  // namespace vaultstorm
