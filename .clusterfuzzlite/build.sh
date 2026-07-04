#!/bin/bash -eu
cd "${SRC:-.}/VaultStorm" 2>/dev/null || cd "${SRC:-.}"
mkdir -p "$OUT"
COMMON_SRC=(src/*.cpp)
for target in policy token envelope redactor graph query telemetry attestation package workflow; do
  "$CXX" $CXXFLAGS -std=c++17 -Iinclude "${COMMON_SRC[@]}" \
    "fuzz/${target}_fuzzer.cc" $LIB_FUZZING_ENGINE -o "$OUT/${target}_fuzzer"
done
