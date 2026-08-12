#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

run() {
  local description="$1"
  shift
  printf '\n--- %s ---\n' "$description"
  "$@"
}

echo "======================================================================"
echo " Starting AF_XDP QUIC Appliance v1 Gate"
echo "======================================================================"

if [[ "$(id -u)" == "0" ]]; then
  V1_PRIVILEGE=(env)
else
  V1_PRIVILEGE=(sudo -E env)
fi

mapfile -t V1_SHELL_SCRIPTS < <(
  find script -type f \( -name '*.sh' -o -path 'script/git-hooks/pre-push' \) -print | sort
)
for script in "${V1_SHELL_SCRIPTS[@]}"; do
  run "Shell syntax: $script" bash -n "$script"
done
run "Python syntax: v1 traffic helper" \
  env PYTHONPYCACHEPREFIX="${TMPDIR:-/tmp}/new_proxy_pycache" \
  python3 -m py_compile script/acceptance/v1/traffic.py

run "Rust formatting" cargo fmt --check
run "v1 Cargo check" cargo check --offline --all-targets
run "v1 Clippy" cargo clippy --offline --all-targets -- -D warnings
run "v1 unit tests" cargo test --offline --lib
run "v1 integration tests" cargo test --offline --test v1_flow_integration

V1_E2E_SCRIPTS=(
  "script/acceptance/v1/e2e_v1_client_to_target.sh"
  "script/acceptance/v1/e2e_v1_server_return.sh"
  "script/acceptance/v1/e2e_v1_client_return.sh"
  "script/acceptance/v1/e2e_v1_same_interface.sh"
  "script/acceptance/v1/e2e_v1_multi_intercept.sh"
  "script/acceptance/v1/e2e_v1_recovery.sh"
  "script/acceptance/v1/e2e_v1_reliability.sh"
)

if [[ "${RUN_V1_E2E:-0}" == "1" || "${RUN_V1_SOAK:-0}" == "1" || "${RUN_V1_PERF:-0}" == "1" ]]; then
  run "v1 release binary" cargo build --offline --release --bin new_proxy
fi

if [[ "${RUN_V1_E2E:-0}" == "1" ]]; then
  for script in "${V1_E2E_SCRIPTS[@]}"; do
    run "v1 E2E: $script" timeout --kill-after=10s 300s \
      "${V1_PRIVILEGE[@]}" V1_BIN="$ROOT_DIR/target/release/new_proxy" bash "$script"
  done
else
  echo
  echo "Privileged v1 E2E deferred; set RUN_V1_E2E=1 to run all seven scenarios."
fi

if [[ "${RUN_V1_SOAK:-0}" == "1" ]]; then
  run "v1 bounded soak" timeout --kill-after=10s "${V1_SOAK_TIMEOUT_SECONDS:-1800}s" \
    "${V1_PRIVILEGE[@]}" \
      V1_BIN="$ROOT_DIR/target/release/new_proxy" \
      RUN_V1_SOAK=1 \
      V1_SOAK_CYCLES="${V1_SOAK_CYCLES:-10}" \
      V1_SOAK_RSS_GROWTH_KB="${V1_SOAK_RSS_GROWTH_KB:-32768}" \
      bash script/acceptance/v1/soak_v1.sh
fi

if [[ "${RUN_V1_PERF:-0}" == "1" ]]; then
  run "v1 performance baseline" timeout --kill-after=10s "${V1_PERF_TIMEOUT_SECONDS:-900}s" \
    "${V1_PRIVILEGE[@]}" \
      V1_BIN="$ROOT_DIR/target/release/new_proxy" \
      RUN_V1_PERF=1 \
      V1_PERF_ITERATIONS="${V1_PERF_ITERATIONS:-100}" \
      bash script/perf/perf_v1.sh
fi

echo
echo "AF_XDP QUIC Appliance v1 gate passed."
