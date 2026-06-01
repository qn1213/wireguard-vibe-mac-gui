#!/usr/bin/env bash
set -euo pipefail

printf 'Removing WireGuardC privileged helper. macOS may ask for the admin password once.\n'
sudo rm -f /etc/sudoers.d/wireguardc
sudo rm -rf /usr/local/libexec/wireguardc
printf 'Removed WireGuardC privileged helper.\n'
