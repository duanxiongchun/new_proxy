#!/usr/bin/env bash
set -euo pipefail

new_proxy_select_wireguard_backend() {
  local probe="np_wg_probe_$$"

  unset NEW_PROXY_WG_USERSPACE

  if ip link add dev "$probe" type wireguard >/dev/null 2>&1; then
    ip link del dev "$probe" >/dev/null 2>&1 || true
    echo "Using kernel WireGuard backend"
    return 0
  fi
  ip link del dev "$probe" >/dev/null 2>&1 || true

  export NEW_PROXY_WG_USERSPACE=1
  if [ -n "${NEW_PROXY_WG_USERSPACE_CMD:-}" ]; then
    echo "Using userspace WireGuard backend: ${NEW_PROXY_WG_USERSPACE_CMD}"
    return 0
  fi
  if command -v wireguard-go >/dev/null 2>&1; then
    export NEW_PROXY_WG_USERSPACE_CMD="wireguard-go"
    echo "Using userspace WireGuard backend: wireguard-go"
    return 0
  fi
  if command -v boringtun >/dev/null 2>&1; then
    export NEW_PROXY_WG_USERSPACE_CMD="boringtun"
    echo "Using userspace WireGuard backend: boringtun"
    return 0
  fi

  echo "Kernel WireGuard is unavailable and no userspace backend was found." >&2
  echo "Install wireguard-go/boringtun or set NEW_PROXY_WG_USERSPACE_CMD." >&2
  exit 1
}
