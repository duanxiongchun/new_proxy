#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
UNIT="$ROOT_DIR/script/new_proxy@.service"
TEMP_UNIT="$(mktemp /tmp/new_proxy-unit.XXXXXX.service)"
trap 'rm -f "$TEMP_UNIT"' EXIT

sed \
  's#ExecStart=/usr/bin/new_proxy --config /etc/new_proxy/%i.conf#ExecStart=/bin/true#' \
  "$UNIT" >"$TEMP_UNIT"
systemd-analyze verify --man=no "$TEMP_UNIT" >/dev/null

required_unit_lines=(
  'RuntimeDirectoryPreserve=yes'
  'UMask=0077'
  'ProtectSystem=strict'
  'ProtectKernelTunables=true'
  'CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_ADMIN'
  'ReadWritePaths=/sys/fs/bpf /run/new_proxy'
)
for line in "${required_unit_lines[@]}"; do
  grep -Fxq "$line" "$UNIT" || {
    echo "missing required systemd directive: $line" >&2
    exit 1
  }
done

grep -Fq \
  'sudo install -o root -g root -m 0600 conf/server.conf /etc/new_proxy/server.conf' \
  "$ROOT_DIR/README.md"
