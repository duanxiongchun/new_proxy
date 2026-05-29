#!/usr/bin/env bash
set -euo pipefail

require_test_key_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command for test key generation: $1" >&2
    exit 1
  fi
}

new_proxy_generate_test_keypair() {
  local prefix="$1"
  local private_key
  local public_key

  require_test_key_cmd wg
  private_key="$(wg genkey)"
  public_key="$(printf '%s\n' "$private_key" | wg pubkey)"

  printf -v "${prefix}_PRIVATE_KEY" '%s' "$private_key"
  printf -v "${prefix}_PUBLIC_KEY" '%s' "$public_key"
}

new_proxy_generate_test_public_key() {
  local name="$1"
  local private_key
  local public_key

  require_test_key_cmd wg
  private_key="$(wg genkey)"
  public_key="$(printf '%s\n' "$private_key" | wg pubkey)"

  printf -v "$name" '%s' "$public_key"
}

new_proxy_generate_test_keypair NEW_PROXY_TEST_SERVER
new_proxy_generate_test_keypair NEW_PROXY_TEST_CLIENT1
new_proxy_generate_test_keypair NEW_PROXY_TEST_CLIENT2
new_proxy_generate_test_public_key NEW_PROXY_TEST_CLIENT3_PUBLIC_KEY
new_proxy_generate_test_public_key NEW_PROXY_TEST_CLIENT4_PUBLIC_KEY
