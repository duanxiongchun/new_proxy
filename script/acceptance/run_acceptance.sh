#!/usr/bin/env bash
# ==============================================================================
# new_proxy Unified Acceptance Test Runner
# ==============================================================================
set -u

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT_DIR"

echo "======================================================================"
echo " Starting Unified Acceptance Tests"
echo "======================================================================"

# 1. Run Rust static checks and unit tests
echo "--- Checking Rust Formatting ---"
if ! cargo fmt --check; then
  echo "❌ Rust formatting check failed!" >&2
  exit 1
fi
echo "✅ Rust formatting check passed."

echo "--- Running Cargo Check ---"
if ! cargo check --quiet; then
  echo "❌ Cargo check failed!" >&2
  exit 1
fi
echo "✅ Cargo check passed."

echo "--- Running Clippy ---"
if ! cargo clippy --all-targets -- -D warnings; then
  echo "❌ Clippy failed!" >&2
  exit 1
fi
echo "✅ Clippy passed."

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

if [ "${RUN_PERF:-0}" = "1" ]; then
  echo "--- Building Release Binaries For Perf ---"
  if ! cargo build --release --bins; then
    echo "❌ Release build failed!" >&2
    exit 1
  fi
  echo "✅ Release build succeeded."
fi

# 3. Compile/Syntax checks on scripts
echo "--- Checking Scripts Syntax ---"
bash_scripts=(
  "script/acceptance/e2e_test_dualstack.sh"
  "script/acceptance/e2e_scenarios.sh"
  "script/acceptance/e2e_multi_client.sh"
  "script/acceptance/e2e_dynamic_client_peer.sh"
  "script/acceptance/e2e_client_topology_gate.sh"
  "script/acceptance/e2e_userspace_wg_fallback.sh"
  "script/acceptance/e2e_full_tunnel_bypass.sh"
  "script/acceptance/e2e_udp_icmp_tunnel.sh"
  "script/acceptance/stability_stress_test.sh"
  "script/perf/perf_smoke.sh"
  "script/perf/perf_cores_scalability.sh"
)

for s in "${bash_scripts[@]}"; do
  if ! bash -n "$s"; then
    echo "❌ Syntax check failed for $s" >&2
    exit 1
  fi
done
echo "✅ Script syntax checks passed."

echo "--- Checking Python Helpers ---"
if ! python3 -m py_compile \
  script/acceptance/stability_report.py \
  script/acceptance/stability_server.py \
  script/acceptance/stability_long_tcp.py; then
  echo "❌ Python helper syntax check failed!" >&2
  exit 1
fi
echo "✅ Python helper syntax checks passed."

# 4. Run E2E scenarios
TESTS=(
  "e2e_test_dualstack"
  "e2e_scenarios"
  "e2e_multi_client"
  "e2e_dynamic_client_peer"
  "e2e_client_topology_gate"
  "e2e_userspace_wg_fallback"
  "e2e_full_tunnel_bypass"
  "e2e_udp_icmp_tunnel"
)

if [ "${RUN_STABILITY:-0}" = "1" ]; then
  TESTS+=("stability_stress_test")
fi

if [ "${RUN_PERF:-0}" = "1" ]; then
  TESTS+=("../perf/perf_smoke")
  TESTS+=("../perf/perf_cores_scalability")
fi

declare -A RESULTS
FAILED=0

for test_name in "${TESTS[@]}"; do
  echo "======================================================================"
  echo " Running E2E Test: $test_name"
  echo "======================================================================"
  
  if sudo bash "script/acceptance/${test_name}.sh"; then
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
