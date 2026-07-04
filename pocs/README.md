# VaultStorm PoCs

Each file is exact input bytes for one connected fuzzing target. The inputs are
logic-invariant crashes rather than toy one-byte gates.

| PoC | Expected target |
| --- | --- |
| `policy_shadow_breakglass.poc` | `policy_fuzzer` |
| `token_unsigned_delegated_root.poc` | `token_fuzzer` |
| `envelope_resumable_truncated_mac.poc` | `envelope_fuzzer` |
| `redactor_public_apikey_tail.poc` | `redactor_fuzzer` |
| `graph_public_root_infinite.poc` | `graph_fuzzer` |
| `query_unbounded_secret_wildcard.poc` | `query_fuzzer` |
| `telemetry_impossible_suppressed.poc` | `telemetry_fuzzer` |
| `attestation_debug_prod.poc` | `attestation_fuzzer` |
| `package_late_traversal.poc` | `package_fuzzer` |
| `workflow_self_approval.poc` | `workflow_fuzzer` |
