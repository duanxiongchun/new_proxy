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

run "Rust formatting" cargo fmt --check
run "Cargo check" cargo check
run "Clippy" cargo clippy --all-targets -- -D warnings
run "v1 unit tests" cargo test --lib v1_unit_
run "v1 integration tests" cargo test --test v1_flow_integration
run "all Rust tests" cargo test
run "binary build" cargo build --bins

V1_E2E_SCRIPTS=(
  "script/acceptance/v1/e2e_v1_client_to_target.sh"
  "script/acceptance/v1/e2e_v1_server_return.sh"
  "script/acceptance/v1/e2e_v1_client_return.sh"
  "script/acceptance/v1/e2e_v1_same_interface.sh"
  "script/acceptance/v1/e2e_v1_multi_intercept.sh"
  "script/acceptance/v1/e2e_v1_recovery.sh"
)

if [[ "${RUN_V1_E2E:-0}" == "1" ]]; then
  for script in "${V1_E2E_SCRIPTS[@]}"; do
    if [[ ! -f "$script" ]]; then
      echo "Missing required v1 E2E script: $script" >&2
      exit 1
    fi
    run "Shell syntax: $script" bash -n "$script"
  done

  for script in "${V1_E2E_SCRIPTS[@]}"; do
    run "v1 E2E: $script" timeout --kill-after=10s 300s sudo -E bash "$script"
  done
else
  echo
  echo "Privileged v1 E2E deferred; set RUN_V1_E2E=1 after the six v1 scenarios exist."
fi

echo
echo "AF_XDP QUIC Appliance v1 gate passed."
