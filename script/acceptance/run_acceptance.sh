#!/usr/bin/env bash
# ==============================================================================
# new_proxy Unified Acceptance Test Runner
# ==============================================================================
set -u

if [ "$EUID" -ne 0 ]; then
  echo "Error: This script must be run as root / using sudo." >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT_DIR"

echo "======================================================================"
echo " Starting Unified Acceptance Tests"
echo "======================================================================"

# 1. Run Cargo Tests
echo "--- Running Unit Tests ---"
if ! cargo test --quiet; then
  echo "❌ Unit tests failed!" >&2
  exit 1
fi
echo "✅ Unit tests passed."

# 2. Build Binaries
echo "--- Building Binaries ---"
if ! cargo build --bins; then
  echo "❌ Build failed!" >&2
  exit 1
fi
echo "✅ Build succeeded."

# 3. Compile/Syntax checks on scripts
echo "--- Checking Scripts Syntax ---"
bash_scripts=(
  "script/acceptance/e2e_test_dualstack.sh"
  "script/acceptance/e2e_scenarios.sh"
  "script/acceptance/e2e_multi_client.sh"
  "script/acceptance/e2e_dynamic_client_peer.sh"
  "script/acceptance/e2e_userspace_wg_fallback.sh"
  "script/acceptance/e2e_full_tunnel_bypass.sh"
)

for s in "${bash_scripts[@]}"; do
  if ! bash -n "$s"; then
    echo "❌ Syntax check failed for $s" >&2
    exit 1
  fi
done
echo "✅ Script syntax checks passed."

# 4. Run E2E scenarios
TESTS=(
  "e2e_test_dualstack"
  "e2e_scenarios"
  "e2e_multi_client"
  "e2e_dynamic_client_peer"
  "e2e_userspace_wg_fallback"
  "e2e_full_tunnel_bypass"
)

declare -A RESULTS
FAILED=0

for test_name in "${TESTS[@]}"; do
  echo "======================================================================"
  echo " Running E2E Test: $test_name"
  echo "======================================================================"
  
  if bash "script/acceptance/${test_name}.sh"; then
    RESULTS["$test_name"]="PASS"
  else
    RESULTS["$test_name"]="FAIL"
    FAILED=$((FAILED + 1))
  fi
done

echo "======================================================================"
echo " Acceptance Test Summary"
echo "======================================================================"
for test_name in "${TESTS[@]}"; do
  printf "%-30s : %s\n" "$test_name" "${RESULTS[$test_name]}"
done
echo "======================================================================"

if [ "$FAILED" -ne 0 ]; then
  echo "❌ Acceptance tests failed! ($FAILED failures)" >&2
  exit 1
else
  echo "✅ All acceptance tests passed successfully!"
  exit 0
fi
