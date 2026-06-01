#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_USER="${SUDO_USER:-$(id -un)}"
BASE_DIR="/usr/local/libexec/wireguardc"
HELPER="$BASE_DIR/wireguardc-root"
ENGINE="$BASE_DIR/wireguardc"
SUDOERS="/etc/sudoers.d/wireguardc"
TMP_SUDOERS="$(mktemp)"

cleanup() {
  rm -f "$TMP_SUDOERS"
}
trap cleanup EXIT

cd "$ROOT_DIR"
go build -trimpath -ldflags "-s -w" -o wireguardc ./cmd/wireguardc

printf 'Installing privileged helper. macOS will ask for the admin password once.\n'
sudo -v

sudo install -d -o root -g wheel -m 755 "$BASE_DIR"
sudo install -o root -g wheel -m 755 "$ROOT_DIR/wireguardc" "$ENGINE"
sudo install -o root -g wheel -m 755 "$ROOT_DIR/scripts/wireguardc-root.sh" "$HELPER"

cat > "$TMP_SUDOERS" <<EOF
$INSTALL_USER ALL=(root) NOPASSWD: $HELPER start, $HELPER start *, $HELPER stop, $HELPER cleanup, $HELPER status
EOF

sudo visudo -cf "$TMP_SUDOERS" >/dev/null
sudo install -o root -g wheel -m 440 "$TMP_SUDOERS" "$SUDOERS"

printf 'Installed:\n'
printf '  %s\n' "$ENGINE"
printf '  %s\n' "$HELPER"
printf '  %s\n' "$SUDOERS"
printf '\nConnect/disconnect will no longer ask for a password after restarting the GUI app.\n'
