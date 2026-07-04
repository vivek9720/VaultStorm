# VaultStorm

VaultStorm is a standalone cybersecurity fuzzing project for exercising logic-heavy
parsers that appear in secret-scanning gateways, policy engines, token brokers,
evidence packages, and SIEM-style event pipelines.  The project intentionally uses
structured inputs with nested framing, accumulated state, and cross-record
invariants so that fuzzing has to drive meaningful code paths instead of toggling a
single branch.

The repository follows the ClusterFuzzLite layout:

- `.clusterfuzzlite/build.sh` builds every harness into `$OUT`.
- `fuzz/` contains connected libFuzzer entry points.
- `fuzz/corpus/<target>/` contains per-target seed corpora.
- `pocs/` contains deterministic proof-of-concept inputs for known fuzzing tasks.

The implementation is first-party C++17 and has no network, credential, or
interactive build requirements.
