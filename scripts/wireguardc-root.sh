#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="/usr/local/libexec/wireguardc"
ENGINE="$BASE_DIR/wireguardc"
CALLER="${SUDO_USER:-$(stat -f '%Su' /dev/console)}"
CALLER_HOME="$(dscl . -read "/Users/$CALLER" NFSHomeDirectory | awk '{print $2}')"
CALLER_GROUP="$(id -gn "$CALLER")"
APP_DIR="$CALLER_HOME/Library/Application Support/WireGuardC"
CONFIG="$APP_DIR/active.conf"
STATS="$APP_DIR/state.json"
PID_FILE="$APP_DIR/tunnel.pid"
LOG_FILE="$APP_DIR/tunnel.log"
ROUTE_STATE="$APP_DIR/routes.json"

die() {
  printf 'wireguardc-root: %s\n' "$*" >&2
  exit 1
}

ensure_runtime_dir() {
  [[ -x "$ENGINE" ]] || die "engine missing: $ENGINE"
  mkdir -p "$APP_DIR"
  chown "$CALLER:$CALLER_GROUP" "$APP_DIR"
  chmod 700 "$APP_DIR"
}

read_pid() {
  [[ -f "$PID_FILE" ]] || return 1
  local pid
  pid="$(tr -dc '0-9' < "$PID_FILE")"
  [[ -n "$pid" ]] || return 1
  printf '%s\n' "$pid"
}

is_running() {
  local pid="$1"
  kill -0 "$pid" >/dev/null 2>&1
}

start() {
  ensure_runtime_dir
  [[ -f "$CONFIG" ]] || die "active config missing: $CONFIG"

  if pid="$(read_pid 2>/dev/null)" && is_running "$pid"; then
    printf 'already running: %s\n' "$pid"
    return 0
  fi

  rm -f "$PID_FILE"
  : > "$LOG_FILE"
  chown "$CALLER:$CALLER_GROUP" "$LOG_FILE"
  chmod 600 "$LOG_FILE"

  "$ENGINE" run \
    -config "$CONFIG" \
    -stats-file "$STATS" \
    -pid-file "$PID_FILE" \
    -route-state-file "$ROUTE_STATE" \
    -owner-pid "${OWNER_PID:-0}" \
    -handshake-timeout 45s \
    >> "$LOG_FILE" 2>&1 &

  printf 'started\n'
}

stop() {
  ensure_runtime_dir
  if ! pid="$(read_pid 2>/dev/null)"; then
    printf 'not running\n'
    return 0
  fi

  if is_running "$pid"; then
    kill -TERM "$pid" >/dev/null 2>&1 || true
    for _ in {1..50}; do
      if ! is_running "$pid"; then
        break
      fi
      sleep 0.1
    done
    if is_running "$pid"; then
      kill -KILL "$pid" >/dev/null 2>&1 || true
    fi
  fi
  rm -f "$PID_FILE"
  "$ENGINE" cleanup-routes -route-state-file "$ROUTE_STATE" >/dev/null 2>&1 || true
  printf 'stopped\n'
}

cleanup() {
  stop >/dev/null 2>&1 || true
  "$ENGINE" cleanup-routes -route-state-file "$ROUTE_STATE" >/dev/null 2>&1 || true
  printf 'cleaned\n'
}

owner_pid_arg() {
  local owner_pid="${1:-0}"
  if [[ "$owner_pid" =~ ^[0-9]+$ ]]; then
    printf '%s\n' "$owner_pid"
  else
    die "owner pid must be numeric"
  fi
}

status() {
  ensure_runtime_dir
  if pid="$(read_pid 2>/dev/null)" && is_running "$pid"; then
    printf 'running %s\n' "$pid"
  else
    printf 'stopped\n'
  fi
}

case "${1:-}" in
  start)
    OWNER_PID="$(owner_pid_arg "${2:-0}")"
    start
    ;;
  stop) stop ;;
  cleanup) cleanup ;;
  status) status ;;
  *) die "usage: $0 start|stop|cleanup|status" ;;
esac
